# ML_Project

## Data Pre-processing Script
* pre_processing.py in the Pre-Processing folder reads benign and malicious file paths from two text files and transforms them into enriched CSV datasets for further analysis.
  
* `pip install -r requirements.txt`
* `python pre_processing.py benign_full_filepaths.txt malicious_full_filepaths.txt`

* Generates multiple CSV outputs including:
	 * final_full.csv: All data combined (benign + malicious), deduplicated.
	* final_5000.csv: A balanced 5,000-row dataset for ML training.
	* final_10000.csv: A balanced 10,000-row dataset for ML training.

## Everything else
* Everything else is in the ipynb