# CryptoAudit Pro

A comprehensive cryptocurrency token audit tool built with modern web technologies and blockchain integration.

## Features

### 🔒 Security Analysis
- Real-time smart contract security assessment
- Scam detection
- Risk scoring with detailed analysis
- Buy/sell restriction detection

### 📱 Social Sentiment Analysis (Unique Feature #2)
- Real-time social media monitoring
- Influencer mention tracking
- Community health scoring

### 📊 Token Analytics
- Complete token information extraction
- Liquidity pool analysis across multiple DEXs
- Transaction volume and holder statistics
- Owner and contract analysis

### 📈 Real-time Data
- Live blockchain data integration
- Transaction monitoring
- Liquidity tracking
- Holder distribution analysis

### 📄 Professional Reporting
- Exportable PDF reports
- Comprehensive audit summaries
- Professional formatting
- Branded documentation
- AI insights and social data included

### 🎨 Modern UI/UX
- Dark/light mode toggle
- Responsive design
- Glassmorphism effects
- Smooth animations and transitions

## Technology Stack

### Frontend
- **React 18** with TypeScript
- **Tailwind CSS** for styling
- **Lucide React** for icons
- **Vite** for development and building

### Blockchain
- **Ethers.js** for blockchain interaction
- **Hardhat** for smart contract development
- **Solidity** for contract analysis tools

### Utilities
- **jsPDF** for report generation
- **html2canvas** for component export
- **Axios** for API requests
- **OpenAI API** for AI risk prediction

## Getting Started

### Prerequisites
- Node.js 18+ 
- npm or yarn

### Live Link

https://project-lgbq.vercel.app/

### Installation

1. Clone the repository
```bash
git clone <repository-url>
cd crypto-audit-pro
```

2. Install dependencies
```bash
npm install
```

3. Configure environment variables
```bash
cp .env.example .env
# Edit .env with your API keys and contract addresses
```

4. Start the development server
```bash
npm run dev
```

5. (Optional) Run Hardhat node for local blockchain testing
```bash
npm run node
```

### Environment Configuration

Create a `.env` file with the following variables:

```env
# Required - Blockchain APIs
VITE_ALCHEMY_API_KEY=your_alchemy_api_key
VITE_ETHERSCAN_API_KEY=your_etherscan_api_key

# Required - Smart Contract Addresses
VITE_TOKEN_ANALYZER_ADDRESS=your_contract_address
VITE_AUDIT_REGISTRY_ADDRESS=your_contract_address
VITE_SCAM_DETECTOR_ADDRESS=your_contract_address

# Optional - AI Features
VITE_OPENAI_API_KEY=your_openai_api_key
VITE_TWITTER_BEARER_TOKEN=your_twitter_bearer_token
```

### Usage

1. **Token Analysis**: Enter a token contract address to start the audit
2. **AI Insights**: Get machine learning risk predictions
3. **Social Analysis**: Monitor community sentiment and social buzz
4. **Review Results**: Analyze comprehensive security and market data
5. **Export Report**: Generate professional PDF reports with all insights
6. **Dark Mode**: Toggle between light and dark themes

## Smart Contract Integration

The application includes a Solidity contract for on-chain token analysis:

- **TokenAnalyzer.sol**: Advanced contract analysis functions
- **Security Flags**: Automated detection of risky functions
- **Batch Analysis**: Analyze multiple tokens efficiently
- **Risk Scoring**: Algorithmic risk assessment
