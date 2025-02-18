# CloudConfigAnalyzer
## Features

- Analyze JSON files for cloud infrastructure security issues
- Provide recommendations for improving security
- Run locally or deploy to Google Cloud Platform

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/garcrod/CloudConfigAnalyzer.git
    cd CloudConfigAnalyzer
    ```

2. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Run Locally

To run the tool locally, use the following command:
```bash
python3 main.py
```
And browse to http://localhost:8000

### Deploy to GCP

1. Update the `app.yaml` file with your service name.
2. Deploy the application to Google Cloud Platform:
    ```bash
    gcloud app deploy
    ```
3. Browse to your deployed service:
    ```bash
    gcloud app browse -s NAME_OF_YOUR_SERVICE
    ```
