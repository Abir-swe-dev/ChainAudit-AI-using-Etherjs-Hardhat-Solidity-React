// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

interface IERC20Extended {
    function name()        external view returns (string memory);
    function symbol()      external view returns (string memory);
    function decimals()    external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function owner()       external view returns (address);
}


contract TokenAnalyzer is Ownable, ReentrancyGuard {

    // ─── Structs ─────────────────────────────────────────────────────────────

    struct TokenInfo {
        string  name;
        string  symbol;
        uint8   decimals;
        uint256 totalSupply;
        address owner;
        bool    exists;
        bool    supplyAboveThreshold; // totalSupply > 1 trillion tokens
    }

    struct SecurityFlags {
        bool hasOwner;
        bool hasMintFunction;
        bool hasBurnFunction;
        bool hasPauseFunction;
        bool hasBlacklistFunction;
        bool ownershipRenounced;
    }

    struct AuditResult {
        TokenInfo     info;
        SecurityFlags flags;
        uint256       rawAuditScore;  // Σ wᵢ·fᵢ (×100 scaled)
        uint256       auditRiskScore; // normalized 0–100
        uint8         riskLevel;      // 0=Safe 1=Low 2=Med 3=High 4=Critical
        uint256       analyzedAt;
    }

    // ─── XGBoost Leaf Weights (×100 integer math) ────────────────────────────

    uint256 private constant W_BLACKLIST_FN     = 3000;
    uint256 private constant W_MINT_NO_RENOUNCE = 2500;
    uint256 private constant W_MINT_FN          = 2000;
    uint256 private constant W_OWNER_NO_RENOUNCE= 1200;
    uint256 private constant W_SUPPLY_HIGH      = 1100;
    uint256 private constant W_PAUSE_FN         = 1500;
    uint256 private constant W_NO_BURN          = 1000;
    uint256 private constant W_DECIMALS_9       =  800;
    uint256 private constant W_MAX_AUDIT        = 13100;

    // Supply threshold: 1 trillion tokens × 18 decimals
    uint256 private constant SUPPLY_THRESHOLD =
        1_000_000_000_000 * 1e18;

    // ─── Storage ─────────────────────────────────────────────────────────────

    mapping(address => AuditResult)   private auditResults;
    mapping(address => SecurityFlags) private securityAnalysis;

    // ─── Events ──────────────────────────────────────────────────────────────

    event TokenAnalyzed(
        address indexed token,
        address indexed analyzer,
        uint256 auditRiskScore,
        uint8   riskLevel,
        uint256 timestamp
    );

    // ─── Main Functions ───────────────────────────────────────────────────────

 
    function analyzeToken(address tokenAddress)
        external
        nonReentrant
        returns (AuditResult memory result)
    {
        require(tokenAddress != address(0), "Invalid token address");

        // ── Fetch token metadata ─────────────────────────────────────────────
        result.info = _fetchTokenInfo(tokenAddress);

        // ── Fetch security flags from storage (set by owner/auditor) ─────────
        result.flags = securityAnalysis[tokenAddress];

        // ── XGBoost additive scoring: SCORE = Σ wᵢ·fᵢ ───────────────────────
        uint256 score = 0;

        if (result.flags.hasBlacklistFunction)
            score += W_BLACKLIST_FN;

        if (result.flags.hasMintFunction && !result.flags.ownershipRenounced)
            score += W_MINT_NO_RENOUNCE;

        if (result.flags.hasMintFunction)
            score += W_MINT_FN;

        if (result.flags.hasOwner && !result.flags.ownershipRenounced)
            score += W_OWNER_NO_RENOUNCE;

        if (result.info.supplyAboveThreshold)
            score += W_SUPPLY_HIGH;

        if (result.flags.hasPauseFunction)
            score += W_PAUSE_FN;

        if (!result.flags.hasBurnFunction)
            score += W_NO_BURN;

        if (result.info.decimals == 9)
            score += W_DECIMALS_9;

        result.rawAuditScore  = score;
        result.auditRiskScore = (score * 100) / W_MAX_AUDIT;

        // ── Risk level bucketing ─────────────────────────────────────────────
        if      (result.auditRiskScore < 15) result.riskLevel = 0;  // Safe
        else if (result.auditRiskScore < 35) result.riskLevel = 1;  // Low
        else if (result.auditRiskScore < 60) result.riskLevel = 2;  // Medium
        else if (result.auditRiskScore < 80) result.riskLevel = 3;  // High
        else                                 result.riskLevel = 4;  // Critical

        result.analyzedAt = block.timestamp;
        auditResults[tokenAddress] = result;

        emit TokenAnalyzed(
            tokenAddress,
            msg.sender,
            result.auditRiskScore,
            result.riskLevel,
            block.timestamp
        );

        return result;
    }

  
    function batchAnalyze(address[] calldata tokens)
        external
        nonReentrant
        returns (AuditResult[] memory results)
    {
        require(tokens.length <= 10, "Max 10 tokens per batch");
        results = new AuditResult[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            results[i] = this.analyzeToken(tokens[i]);
        }
    }

  
    function setSecurityFlags(
        address tokenAddress,
        bool hasOwner,
        bool hasMintFunction,
        bool hasBurnFunction,
        bool hasPauseFunction,
        bool hasBlacklistFunction,
        bool ownershipRenounced
    ) external onlyOwner {
        securityAnalysis[tokenAddress] = SecurityFlags({
            hasOwner:             hasOwner,
            hasMintFunction:      hasMintFunction,
            hasBurnFunction:      hasBurnFunction,
            hasPauseFunction:     hasPauseFunction,
            hasBlacklistFunction: hasBlacklistFunction,
            ownershipRenounced:   ownershipRenounced
        });
    }

    // ─── Views ────────────────────────────────────────────────────────────────

    function getAuditResult(address tokenAddress)
        external view returns (AuditResult memory)
    {
        return auditResults[tokenAddress];
    }

    function getTokenInfo(address tokenAddress)
        external view returns (TokenInfo memory)
    {
        return auditResults[tokenAddress].info;
    }

    function checkSecurityFlags(address tokenAddress)
        external view returns (SecurityFlags memory)
    {
        return securityAnalysis[tokenAddress];
    }

  
    function getModelWeights()
        external pure
        returns (
            uint256 wBlacklistFn,
            uint256 wMintNoRenounce,
            uint256 wMintFn,
            uint256 wOwnerNoRenounce,
            uint256 wSupplyHigh,
            uint256 wPauseFn,
            uint256 wNoBurn,
            uint256 wDecimals9,
            uint256 wMax
        )
    {
        return (
            W_BLACKLIST_FN,
            W_MINT_NO_RENOUNCE,
            W_MINT_FN,
            W_OWNER_NO_RENOUNCE,
            W_SUPPLY_HIGH,
            W_PAUSE_FN,
            W_NO_BURN,
            W_DECIMALS_9,
            W_MAX_AUDIT
        );
    }

    // ─── Internal Helpers ─────────────────────────────────────────────────────

    function _fetchTokenInfo(address tokenAddress)
        internal view returns (TokenInfo memory info)
    {
        try IERC20Extended(tokenAddress).name() returns (string memory n) {
            info.name = n;
        } catch {
            info.name = _addressToString(tokenAddress);
        }

        try IERC20Extended(tokenAddress).symbol() returns (string memory sym) {
            info.symbol = sym;
        } catch {
            info.symbol = _addressToShortString(tokenAddress);
        }

        try IERC20Extended(tokenAddress).decimals() returns (uint8 dec) {
            info.decimals = dec;
        } catch {
            info.decimals = 18;
        }

        try IERC20Extended(tokenAddress).totalSupply() returns (uint256 supply) {
            info.totalSupply = supply;
            info.exists = true;
            info.supplyAboveThreshold = supply > SUPPLY_THRESHOLD;
        } catch {
            info.totalSupply = 0;
            info.exists      = false;
        }

        try IERC20Extended(tokenAddress).owner() returns (address ownerAddr) {
            info.owner = ownerAddr;
        } catch {
            info.owner = address(0);
        }
    }

    function _addressToString(address _addr)
        internal pure returns (string memory)
    {
        bytes32 value    = bytes32(uint256(uint160(_addr)));
        bytes memory abc = "0123456789abcdef";
        bytes memory str = new bytes(42);
        str[0] = '0'; str[1] = 'x';
        for (uint256 i = 0; i < 20; i++) {
            str[2+i*2] = abc[uint8(value[i+12] >> 4)];
            str[3+i*2] = abc[uint8(value[i+12] & 0x0f)];
        }
        return string(str);
    }

    function _addressToShortString(address _addr)
        internal pure returns (string memory)
    {
        bytes32 value    = bytes32(uint256(uint160(_addr)));
        bytes memory abc = "0123456789abcdef";
        bytes memory str = new bytes(6);
        for (uint256 i = 0; i < 3; i++) {
            str[i*2]   = abc[uint8(value[i+12] >> 4)];
            str[i*2+1] = abc[uint8(value[i+12] & 0x0f)];
        }
        return string(str);
    }
}
