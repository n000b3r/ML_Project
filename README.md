# ML_Project

## Data pre-processing script
* pre_processing.py reads in benign and malicious file paths from two text files and processes them into enriched CSV datasets for further analysis.

* ` python pre_processing.py benign_full_filepaths.txt malicious_full_filepaths.txt`

* Generates multiple CSV outputs including:
	 * final_full.csv: All data combined (benign + malicious), deduplicated.
	* final_5000.csv: A limited 5,000-row dataset
	* final_10000.csv: A limited 10,000-row dataset.

