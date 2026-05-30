// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";


contract AuditRegistry is Ownable, ReentrancyGuard {

    // ─── Structs ─────────────────────────────────────────────────────────────

    struct AuditRecord {
        address tokenAddress;
        uint256 gbScore;          // from ScamDetector  (0–100)
        uint256 xgbScore;         // from TokenAnalyzer (0–100)
        uint256 rfScore;          // RF ensemble score  (0–100)
        uint256 combinedScore;    // weighted average   (0–100)
        bool    isScam;
        bool    isHoneypot;
        uint8   rfVotes;          // how many of 7 trees voted scam
        uint256 auditTimestamp;
        address auditor;
        string  ipfsHash;
    }

    struct TokenMetrics {
        uint256 totalTransactions;
        uint256 uniqueHolders;
        uint256 liquidityUSD;
        bool    liquidityLocked;
        uint256 buyTaxPct;
        uint256 sellTaxPct;
        bool    contractVerified;
        uint256 ageDays;
        uint256 auditCount;
        uint256 lastUpdated;
    }

    // ─── RF Ensemble Weights (×100 integer math) ─────────────────────────────
    // Combined score = (W_GB×gbScore + W_XGB×xgbScore + W_RF×rfScore) / 100

    uint256 private constant W_GB   = 45;   // ScamDetector weight
    uint256 private constant W_XGB  = 30;   // TokenAnalyzer weight
    uint256 private constant W_RF   = 25;   // AuditRegistry RF weight

    // RF threshold: ≥ 4 out of 7 trees vote scam → is scam
    uint8   private constant RF_TREES         = 7;
    uint8   private constant RF_VOTE_THRESHOLD = 4;

    // ─── Thresholds for RF decision stumps ───────────────────────────────────
    // Derived from offline RF training on 5500-row dataset

    uint256 private constant T4_HOLDER_THRESHOLD  = 500;
    uint256 private constant T4_AGE_THRESHOLD      = 30;
    uint256 private constant T5_LIQUIDITY_THRESHOLD = 50_000;  // USD
    uint256 private constant T3_TAX_THRESHOLD       = 20;      // %
    uint256 private constant T2_RISK_THRESHOLD      = 70;      // risk score

    // ─── Storage ─────────────────────────────────────────────────────────────

    mapping(address => AuditRecord)  public auditRecords;
    mapping(address => TokenMetrics) public tokenMetrics;
    mapping(address => bool)         public authorizedAuditors;
    mapping(address => uint256)      public auditCount;

    // ─── Events ──────────────────────────────────────────────────────────────

    event AuditCompleted(
        address indexed token,
        address indexed auditor,
        uint256 combinedScore,
        uint8   rfVotes,
        bool    isScam,
        uint256 timestamp
    );
    event TokenMetricsUpdated(
        address indexed token,
        uint256 transactions,
        uint256 holders,
        uint256 liquidity,
        uint256 timestamp
    );

    // ─── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyAuthorizedAuditor() {
        require(
            authorizedAuditors[msg.sender] || msg.sender == owner(),
            "Not authorized auditor"
        );
        _;
    }

    // ─── Constructor ─────────────────────────────────────────────────────────

    constructor() {
        authorizedAuditors[msg.sender] = true;
    }

    // ─── Main Audit Function ──────────────────────────────────────────────────

    
    function submitAuditResult(
        address tokenAddress,
        uint256 gbScore,
        uint256 xgbScore,
        bool    isHoneypot,
        string calldata ipfsHash
    ) external onlyAuthorizedAuditor nonReentrant {
        require(tokenAddress != address(0), "Invalid token address");
        require(gbScore  <= 100, "gbScore must be <= 100");
        require(xgbScore <= 100, "xgbScore must be <= 100");

        TokenMetrics memory m = tokenMetrics[tokenAddress];

        // ── Random Forest: run 7 decision trees ─────────────────────────────
        uint8 votes = _runRandomForest(gbScore, m);

        // ── RF score: (votes / T) × 100 ─────────────────────────────────────
        uint256 rfScore = (uint256(votes) * 100) / uint256(RF_TREES);

        // ── Combined weighted score ──────────────────────────────────────────
        // FINAL = (45×gbScore + 30×xgbScore + 25×rfScore) / 100
        uint256 combinedScore =
            (W_GB * gbScore + W_XGB * xgbScore + W_RF * rfScore) / 100;

        bool isScam = votes >= RF_VOTE_THRESHOLD || isHoneypot;

        auditRecords[tokenAddress] = AuditRecord({
            tokenAddress:   tokenAddress,
            gbScore:        gbScore,
            xgbScore:       xgbScore,
            rfScore:        rfScore,
            combinedScore:  combinedScore,
            isScam:         isScam,
            isHoneypot:     isHoneypot,
            rfVotes:        votes,
            auditTimestamp: block.timestamp,
            auditor:        msg.sender,
            ipfsHash:       ipfsHash
        });

        auditCount[msg.sender]++;

        emit AuditCompleted(
            tokenAddress, msg.sender,
            combinedScore, votes, isScam,
            block.timestamp
        );
    }

    // ─── Random Forest: 7 Decision Trees ─────────────────────────────────────

   
    function _runRandomForest(
        uint256 gbScore,
        TokenMetrics memory m
    ) internal pure returns (uint8 votes) {
        votes = 0;
        votes += _tree1(m);
        votes += _tree2(gbScore);
        votes += _tree3(m);
        votes += _tree4(m);
        votes += _tree5(m);
        votes += _tree6(gbScore, m);
        votes += _tree7(m);
    }

 
    function _tree1(TokenMetrics memory m)
        internal pure returns (uint8)
    {
        // Proxy: low liquidity + not locked = likely drain capable
        bool drainProxy    = m.liquidityUSD < T5_LIQUIDITY_THRESHOLD
                             && !m.liquidityLocked;
        // Proxy: very low holder count = blacklist likely active
        bool blacklistProxy = m.uniqueHolders < 200;
        return (drainProxy && blacklistProxy) ? 1 : 0;
    }

  
    function _tree2(uint256 gbScore)
        internal pure returns (uint8)
    {
        return gbScore >= T2_RISK_THRESHOLD ? 1 : 0;
    }


    function _tree3(TokenMetrics memory m)
        internal pure returns (uint8)
    {
        return (m.buyTaxPct >= T3_TAX_THRESHOLD
             || m.sellTaxPct >= T3_TAX_THRESHOLD) ? 1 : 0;
    }

   
    function _tree4(TokenMetrics memory m)
        internal pure returns (uint8)
    {
        return (m.uniqueHolders < T4_HOLDER_THRESHOLD
             && m.ageDays < T4_AGE_THRESHOLD) ? 1 : 0;
    }


    function _tree5(TokenMetrics memory m)
        internal pure returns (uint8)
    {
        return (m.liquidityUSD < T5_LIQUIDITY_THRESHOLD
             && !m.liquidityLocked) ? 1 : 0;
    }


    function _tree6(uint256 gbScore, TokenMetrics memory m)
        internal pure returns (uint8)
    {
        return (gbScore >= 40 && m.auditCount == 0) ? 1 : 0;
    }


    function _tree7(TokenMetrics memory m)
        internal pure returns (uint8)
    {
        return (m.auditCount == 0 && !m.contractVerified) ? 1 : 0;
    }

    // ─── Token Metrics Update ─────────────────────────────────────────────────


    function updateTokenMetrics(
        address tokenAddress,
        uint256 totalTransactions,
        uint256 uniqueHolders,
        uint256 liquidityUSD,
        bool    liquidityLocked,
        uint256 buyTaxPct,
        uint256 sellTaxPct,
        bool    contractVerified,
        uint256 ageDays,
        uint256 auditCount_
    ) external onlyAuthorizedAuditor {
        tokenMetrics[tokenAddress] = TokenMetrics({
            totalTransactions: totalTransactions,
            uniqueHolders:     uniqueHolders,
            liquidityUSD:      liquidityUSD,
            liquidityLocked:   liquidityLocked,
            buyTaxPct:         buyTaxPct,
            sellTaxPct:        sellTaxPct,
            contractVerified:  contractVerified,
            ageDays:           ageDays,
            auditCount:        auditCount_,
            lastUpdated:       block.timestamp
        });
        emit TokenMetricsUpdated(
            tokenAddress, totalTransactions,
            uniqueHolders, liquidityUSD,
            block.timestamp
        );
    }

    // ─── Views ────────────────────────────────────────────────────────────────

    function getAuditRecord(address tokenAddress)
        external view returns (AuditRecord memory)
    {
        return auditRecords[tokenAddress];
    }

    function getTokenMetrics(address tokenAddress)
        external view returns (TokenMetrics memory)
    {
        return tokenMetrics[tokenAddress];
    }

    function isTokenAudited(address tokenAddress)
        external view returns (bool)
    {
        return auditRecords[tokenAddress].auditTimestamp > 0;
    }

    function getAuditorStats(address auditor)
        external view returns (uint256)
    {
        return auditCount[auditor];
    }

    
    function previewRFScore(address tokenAddress, uint256 gbScore)
        external view returns (uint8 votes, uint256 rfScore, bool wouldBeScam)
    {
        TokenMetrics memory m = tokenMetrics[tokenAddress];
        votes      = _runRandomForest(gbScore, m);
        rfScore    = (uint256(votes) * 100) / uint256(RF_TREES);
        wouldBeScam = votes >= RF_VOTE_THRESHOLD;
    }

  
    function getRFModelConfig()
        external pure
        returns (
            uint8  trees,
            uint8  voteThreshold,
            uint256 wGB,
            uint256 wXGB,
            uint256 wRF,
            uint256 holderThreshold,
            uint256 ageThreshold,
            uint256 liquidityThreshold,
            uint256 taxThreshold,
            uint256 riskThreshold
        )
    {
        return (
            RF_TREES, RF_VOTE_THRESHOLD,
            W_GB, W_XGB, W_RF,
            T4_HOLDER_THRESHOLD, T4_AGE_THRESHOLD,
            T5_LIQUIDITY_THRESHOLD, T3_TAX_THRESHOLD,
            T2_RISK_THRESHOLD
        );
    }

    // ─── Admin ────────────────────────────────────────────────────────────────

    function addAuthorizedAuditor(address auditor) external onlyOwner {
        authorizedAuditors[auditor] = true;
    }

    function removeAuthorizedAuditor(address auditor) external onlyOwner {
        authorizedAuditors[auditor] = false;
    }
}
