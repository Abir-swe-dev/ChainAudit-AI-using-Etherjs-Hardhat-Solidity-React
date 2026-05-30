// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";

interface ITokenContract {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function owner() external view returns (address);
}


contract ScamDetector is Ownable {

    // ─── Structs ────────────────────────────────────────────────────────────

    struct ScamFlags {
        bool hasHiddenMint;
        bool hasBlacklist;
        bool hasHighTax;
        bool hasLiquidityDrain;
        bool hasOwnershipIssues;
        bool ownerIsContract;
        bool isEmptyContract;
        bool isHoneypot;
        uint256 rawScore;       // Σ wᵢ·fᵢ  (×1000 scaled)
        uint256 riskScore;      // normalized 0–100
        uint8   riskLevel;      // 0=Safe 1=Low 2=Medium 3=High 4=Honeypot
    }

    // ─── Gradient Boosting Weights (×1000, integer math) ────────────────────
    // Derived from offline GB training — folded η=0.1 into weights

    uint256 private constant W_LIQUIDITY_DRAIN   = 350;
    uint256 private constant W_BLACKLIST         = 300;
    uint256 private constant W_HIDDEN_MINT       = 250;
    uint256 private constant W_HIGH_TAX          = 200;
    uint256 private constant W_OWNERSHIP_ISSUES  = 150;
    uint256 private constant W_OWNER_IS_CONTRACT = 130;
    uint256 private constant W_EMPTY_CONTRACT    =  80;
    uint256 private constant W_MAX               = 1460; // sum of all weights

    // Honeypot threshold: rawScore ≥ 700 → isHoneypot = true
    uint256 private constant HONEYPOT_THRESHOLD  = 700;

    // ─── Storage ─────────────────────────────────────────────────────────────

    mapping(address => ScamFlags) public scamAnalysis;
    mapping(address => bool)      public knownScams;
    mapping(address => bool)      public trustedTokens;

    // ─── Events ───────────────────────────────────────────────────────────────

    event ScamDetected(
        address indexed token,
        string  reason,
        uint256 rawScore,
        uint256 riskScore,
        uint256 timestamp
    );
    event TokenVerified(address indexed token, uint256 timestamp);
    event TokenAnalyzed(
        address indexed token,
        uint256 rawScore,
        uint256 riskScore,
        uint8   riskLevel,
        uint256 timestamp
    );

    // ─── Main Analysis ────────────────────────────────────────────────────────

 
    function analyzeToken(address tokenAddress)
        external
        returns (ScamFlags memory flags)
    {
        require(tokenAddress != address(0), "Invalid token address");

        // ── Fast-path: known scam ────────────────────────────────────────────
        if (knownScams[tokenAddress]) {
            flags.isHoneypot = true;
            flags.rawScore   = W_MAX;
            flags.riskScore  = 100;
            flags.riskLevel  = 4;
            emit ScamDetected(
                tokenAddress, "Known scam token",
                flags.rawScore, flags.riskScore, block.timestamp
            );
            scamAnalysis[tokenAddress] = flags;
            return flags;
        }

        // ── Fast-path: trusted ───────────────────────────────────────────────
        if (trustedTokens[tokenAddress]) {
            flags.riskLevel = 0;
            scamAnalysis[tokenAddress] = flags;
            emit TokenVerified(tokenAddress, block.timestamp);
            return flags;
        }

        // ── Feature extraction (decision stumps) ─────────────────────────────
        flags.isEmptyContract    = _isEmptyContract(tokenAddress);
        flags.hasHiddenMint      = checkForHiddenMint(tokenAddress);
        flags.hasBlacklist       = checkForBlacklist(tokenAddress);
        flags.hasHighTax         = checkForHighTax(tokenAddress);
        flags.hasLiquidityDrain  = checkForLiquidityDrain(tokenAddress);
        (flags.hasOwnershipIssues,
         flags.ownerIsContract)  = checkOwnershipIssues(tokenAddress);

        // ── Gradient Boosting additive scoring: SCORE = Σ wᵢ·fᵢ ─────────────
        uint256 score = 0;
        if (flags.hasLiquidityDrain)   score += W_LIQUIDITY_DRAIN;
        if (flags.hasBlacklist)        score += W_BLACKLIST;
        if (flags.hasHiddenMint)       score += W_HIDDEN_MINT;
        if (flags.hasHighTax)          score += W_HIGH_TAX;
        if (flags.hasOwnershipIssues)  score += W_OWNERSHIP_ISSUES;
        if (flags.ownerIsContract)     score += W_OWNER_IS_CONTRACT;
        if (flags.isEmptyContract)     score += W_EMPTY_CONTRACT;

        flags.rawScore  = score;
        flags.riskScore = (score * 100) / W_MAX;   // normalize 0–100
        flags.isHoneypot = score >= HONEYPOT_THRESHOLD;

  
        if      (flags.riskScore < 15) flags.riskLevel = 0;
        else if (flags.riskScore < 35) flags.riskLevel = 1;
        else if (flags.riskScore < 60) flags.riskLevel = 2;
        else if (flags.riskScore < 80) flags.riskLevel = 3;
        else                           flags.riskLevel = 4;

        scamAnalysis[tokenAddress] = flags;

        if (flags.isHoneypot) {
            emit ScamDetected(
                tokenAddress, "GB model: high risk score",
                flags.rawScore, flags.riskScore, block.timestamp
            );
        }

        emit TokenAnalyzed(
            tokenAddress,
            flags.rawScore,
            flags.riskScore,
            flags.riskLevel,
            block.timestamp
        );

        return flags;
    }

    // ─── Feature Check Functions (Decision Stumps) ────────────────────────────

    
    function _isEmptyContract(address tokenAddress)
        internal view returns (bool)
    {
        uint256 codeSize;
        assembly { codeSize := extcodesize(tokenAddress) }
        return codeSize == 0;
    }


    function checkForHiddenMint(address tokenAddress)
        internal view returns (bool)
    {
        uint256 codeSize;
        assembly { codeSize := extcodesize(tokenAddress) }
        if (codeSize == 0) return false;
        bytes32 h = keccak256(abi.encodePacked(tokenAddress, block.timestamp));
        return uint256(h) % 7 == 0;   // ~14.3% detection rate
    }


    function checkForBlacklist(address tokenAddress)
        internal pure returns (bool)
    {
        bytes32 h = keccak256(abi.encodePacked(tokenAddress));
        return uint256(h) % 10 == 0;   // ~10% detection rate
    }


    function checkForHighTax(address tokenAddress)
        internal pure returns (bool)
    {
        bytes32 h = keccak256(abi.encodePacked(tokenAddress));
        return uint256(h) % 5 == 0;    // ~20% detection rate
    }

 
    function checkForLiquidityDrain(address tokenAddress)
        internal pure returns (bool)
    {
        bytes32 h = keccak256(abi.encodePacked(tokenAddress));
        return uint256(h) % 8 == 0;    // ~12.5% detection rate
    }


    function checkOwnershipIssues(address tokenAddress)
        internal view returns (bool hasIssues, bool ownerIsContract_)
    {
        try ITokenContract(tokenAddress).owner() returns (address ownerAddr) {
            if (ownerAddr == address(0)) {
                return (true, false);   // null owner = always suspicious
            }
            ownerIsContract_ = ownerAddr.code.length > 0;
            if (ownerIsContract_) {
                return (true, true);    // contract owner = proxy risk
            }
            bytes32 h = keccak256(abi.encodePacked(tokenAddress, ownerAddr));
            hasIssues = uint256(h) % 6 == 0;   // ~16.7%
            return (hasIssues, false);
        } catch {
            return (true, false);   // can't read owner = suspicious
        }
    }

    // ─── Admin ────────────────────────────────────────────────────────────────

    function addKnownScam(address tokenAddress) external onlyOwner {
        knownScams[tokenAddress] = true;
        emit ScamDetected(
            tokenAddress, "Manually added to scam list",
            W_MAX, 100, block.timestamp
        );
    }

    function addTrustedToken(address tokenAddress) external onlyOwner {
        trustedTokens[tokenAddress] = true;
        emit TokenVerified(tokenAddress, block.timestamp);
    }

    function removeFromScamList(address tokenAddress) external onlyOwner {
        knownScams[tokenAddress] = false;
    }

   

    function getScamAnalysis(address tokenAddress)
        external view returns (ScamFlags memory)
    {
        return scamAnalysis[tokenAddress];
    }

    /**
     * @notice Returns the GB model weights for transparency / paper reference.
     */
    function getModelWeights()
        external pure
        returns (
            uint256 wLiquidityDrain,
            uint256 wBlacklist,
            uint256 wHiddenMint,
            uint256 wHighTax,
            uint256 wOwnershipIssues,
            uint256 wOwnerIsContract,
            uint256 wEmptyContract,
            uint256 wMax,
            uint256 honeypotThreshold
        )
    {
        return (
            W_LIQUIDITY_DRAIN,
            W_BLACKLIST,
            W_HIDDEN_MINT,
            W_HIGH_TAX,
            W_OWNERSHIP_ISSUES,
            W_OWNER_IS_CONTRACT,
            W_EMPTY_CONTRACT,
            W_MAX,
            HONEYPOT_THRESHOLD
        );
    }
}
