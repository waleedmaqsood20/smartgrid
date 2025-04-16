# Smart Grid Security Implementation and Evaluation Framework

This project implements and evaluates a secure communication system for smart grid infrastructure, focusing on NIST-compliant security measures and performance analysis.

## Features

- AES-256 encryption with ECDSA P-384 signatures (NIST FIPS 197 compliant)
- Comprehensive security testing suite with multiple attack scenarios
- Performance metrics collection and analysis
- NIST SP 800-53 and SP 800-82 compliance verification
- Detailed visualization and reporting
- Scalability testing with multiple meters

## Requirements

- Python 3.8 or higher
- Dependencies listed in `requirements.txt`

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd [repository-name]
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Running Tests

The evaluation framework can be run in two modes:

1. Development mode (smaller test volumes):
```bash
python run_evaluation_tests.py --mode dev
```

2. Production mode (full test suite):
```bash
python run_evaluation_tests.py --mode prod
```

### Test Options

- `--tests`: Specify which tests to run (default: all)
  - Available tests: baseline, mitm, injection, dos, wrong_key, scalability
  - Example: `--tests mitm dos`

- `--report-dir`: Specify custom directory for reports
  - Example: `--report-dir my_reports`

### Generated Output

After running the tests, the following will be generated in the `evaluation_results_[timestamp]` directory:

1. `charts/` - Visualizations of test results including:
   - Attack detection rates
   - Performance metrics
   - Resource usage
   - Security-performance tradeoff
   - DoS attack impact
   - Scalability analysis
2. `report.html` - Comprehensive evaluation report
3. `results_summary.json` - JSON summary of test results

## Security Features

- AES-256 encryption (NIST FIPS 197 compliant)
- ECDSA P-384 signatures (NIST SP 800-57 compliant)
- Rate limiting for DoS protection
- Replay attack prevention with timestamp validation
- Comprehensive error handling and logging
- MITM attack detection
- Data injection protection
- Wrong key detection

## Research Contributions

This implementation contributes to smart grid security research by:

1. Providing a practical implementation of NIST-recommended security controls
2. Demonstrating performance-security tradeoffs in real-world scenarios
3. Offering a comprehensive evaluation framework for security testing
4. Providing empirical data on:
   - Detection rates for various attack types
   - Performance impact of security measures
   - System scalability with multiple meters
   - Resource usage under different conditions
5. Validating NIST compliance through systematic testing
6. Offering reproducible results through automated testing

## License

[Your chosen license]

## Contact

[Your contact information] 