import os
import re
from pathlib import Path
import mimetypes
import pandas as pd
import argparse

pd.options.mode.chained_assignment = None

COMMON_EXTENSIONS = {
    "aac", "adt", "adts", "accdb", "accde", "accdr", "accdt", "aif", "aifc", "aiff", "aspx",
    "avi", "bat", "bin", "bmp", "cab", "cda", "csv", "dif", "dll", "doc", "docm", "docx",
    "dot", "dotx", "eml", "eps", "exe", "flv", "gif", "htm", "html", "ini", "iso", "jar",
    "jpg", "jpeg", "m4a", "mdb", "mid", "midi", "mov", "mp3", "mp4", "mpeg", "mpg", "msi",
    "mui", "pdf", "png", "pot", "potm", "potx", "ppam", "pps", "ppsm", "ppsx", "ppt",
    "pptm", "pptx", "psd", "pst", "pub", "rar", "rtf", "sldm", "sldx", "swf", "sys", "tif",
    "tiff", "tmp", "txt", "vob", "vsd", "vsdm", "vsdx", "vss", "vssm", "vst", "vstm", 
    "vstx", "wav", "wbk", "wks", "wma", "wmd", "wmv", "wmz", "wms", "wpd", "wp5", "xla",
    "xlam", "xll", "xlm", "xls", "xlsm", "xlsx", "xlt", "xltm", "xltx", "xps", "zip"
}

def guess_extensions(filename):
    """Guess the extensions for a given filename, considering only the last two suffixes."""
    path = Path(filename)
    suffixes = path.suffixes[-2:]
    return [s for s in suffixes if s in mimetypes.types_map]

def is_double_ext(filepath):
    """Check if a file has a double extension by validating the second last suffix."""
    path = Path(filepath)
    suffixes = path.suffixes[-2:]
    if len(suffixes) > 1:
        second_last_ext = suffixes[0]
        if second_last_ext in mimetypes.types_map:
            return 1
    return 0 

def extract_filename_and_extension(filepath):
    """Extract the filename and the main extension from the given file path."""
    filepath = str(filepath)
    path = Path(filepath)
    ads_index = filepath.find(":")
    if ads_index != -1:
        filepath = filepath[:ads_index]
    if path.suffixes:
        filename = path.stem
        extension = path.suffixes[-1]
    else:
        filename = path.name
        extension = ""
    if ads_index != -1:
        filename += filepath[ads_index:]
    return filename, extension

def detect_ads(filepath):
    """
    Determine if the file contains alternate data streams (ADS) using simple string logic.
    Assumes a Windows file path contains one colon (e.g. "c:\\...").
    An additional colon indicates the presence of ADS.
    Returns a list with the ADS name (lowercased) if present, otherwise a list with an empty string.
    """
    if filepath.count(':') >= 2:
        parts = filepath.split(":", 2)
        if len(parts) == 3:
            ads_name = parts[2].strip().lower()
            return [ads_name]
        else:
            return [""]
    else:
        return [""]

def clean_path(path):
    """
    Convert the path to lowercase, remove drive letters, and mask usernames in the file paths.
    """
    path = path.lower()
    path = re.sub(r"^[a-z]:", "", path)  # Remove drive letter
    path = re.sub(r"\\users\\[^\\]+", r"\\users\\<username>", path)  # Mask username
    return path

def mask_version(path):
    """Mask version numbers in file paths."""
    version_pattern = r"\d+(\.\d+){1,3}"
    return re.sub(version_pattern, "<version>", path)

def populate_columns(file_paths, is_malicious):
    """
    Process a list of file paths and return a DataFrame with extra columns.
    
    :param file_paths: List of file path strings.
    :param is_malicious: 1 for malicious file paths, 0 for benign.
    :return: DataFrame with columns (Full_Filepath, Filepath, Filename, Extension, Alt_Data_Stream,
             Directory_Depth, Filename_Length, Is_Common_Extension, Contains_Double_Ext, Contains_ADS, Is_Malicious).
    """
    data = []
    for file_path in file_paths:
        # Ensure the file path is in lowercase
        file_path = file_path.lower()
        ads_list = detect_ads(file_path)
        if not ads_list:
            ads_list = [""]
        for ads in ads_list:
            filename, extension = extract_filename_and_extension(file_path)
            contains_double_ext = is_double_ext(file_path)
            directory_path = os.path.dirname(file_path)
            sanitized_full_path = clean_path(mask_version(f"{file_path}:{ads}" if ads else file_path))
            sanitized_directory_path = clean_path(mask_version(directory_path))
            sanitized_filename = clean_path(mask_version(filename))
            data.append({
                "Full_Filepath": sanitized_full_path,
                "Filepath": sanitized_directory_path,
                "Filename": sanitized_filename,
                "Extension": extension,
                "Alt_Data_Stream": ads,
                "Directory_Depth": len([p for p in sanitized_directory_path.split(os.sep) if p]),
                "Filename_Length": len(sanitized_filename),
                "Is_Common_Extension": int(extension.lstrip(".").lower() in COMMON_EXTENSIONS),
                "Contains_Double_Ext": contains_double_ext,
                "Contains_ADS": int(bool(ads)),
                "Is_Malicious": is_malicious
            })
    return pd.DataFrame(data)

def deduplicate_data(data):
    """Remove duplicate rows based on the Full_Filepath column."""
    return data.drop_duplicates(subset=["Full_Filepath"])

def combine_limited_datasets(benign_df, malicious_df, output_file, total_rows):
    """
    Combines benign and malicious datasets to produce a final CSV with exactly total_rows rows.
    
    - All malicious rows are included.
    - For benign (Is_Malicious==0):
         • All rows with ADS (Contains_ADS == 1) are included.
         • From those without ADS, half are chosen from system files and half from user files.
         • System files are further subdivided evenly into four categories:
             - Filepaths containing "\\windows\\winsxs" or "\\windows\\servicing"
             - Filepaths exactly matching "\\windows"
             - Filepaths containing "\\windows\\system32"
             - Filepaths containing "\\windows\\syswow64"
    - If necessary, extra benign rows are sampled to reach the required total.
    - Final rows are randomized before saving.
    """
    benign_df = benign_df.drop_duplicates(subset=["Full_Filepath"])
    malicious_df = malicious_df.drop_duplicates(subset=["Full_Filepath"])
    
    num_malicious = len(malicious_df)
    num_clean_needed = max(0, total_rows - num_malicious)
    
    # Select benign (clean) rows (Is_Malicious==0)
    benign_clean = benign_df[benign_df["Is_Malicious"] == 0]
    
    # Separate benign rows with ADS vs. no ADS
    clean_ads = benign_clean[benign_clean["Contains_ADS"] == 1]
    clean_no_ads = benign_clean[benign_clean["Contains_ADS"] == 0]
    
    # Classify no-ADS rows into system and user.
    # System files: Filepath contains "\windows" (case-insensitive)
    clean_system = clean_no_ads[clean_no_ads["Filepath"].str.contains(r"\\windows", case=False, na=False)]
    clean_user = clean_no_ads[~clean_no_ads["Filepath"].str.contains(r"\\windows", case=False, na=False)]
    
    # Further split system files into four subcategories:
    clean_system_winsxs = clean_system[clean_system["Filepath"].str.contains(r"\\windows\\(?:winsxs|servicing)", case=False, na=False, regex=True)]
    clean_system_windows = clean_system[clean_system["Filepath"].str.fullmatch(r"\\windows", case=False, na=False)]
    clean_system_system32 = clean_system[clean_system["Filepath"].str.contains(r"\\windows\\system32", case=False, na=False, regex=True)]
    clean_system_syswow64 = clean_system[clean_system["Filepath"].str.contains(r"\\windows\\syswow64", case=False, na=False, regex=True)]
    
    num_ads_files = len(clean_ads)
    num_remaining_clean_needed = max(0, num_clean_needed - num_ads_files)
    
    # Split remaining required clean rows equally: half from system, half from user.
    num_system_needed = num_remaining_clean_needed // 2
    num_user_needed = num_remaining_clean_needed - num_system_needed
    
    # Split system files evenly among the four subcategories.
    num_system_winsxs_needed = num_system_needed // 4
    num_system_windows_needed = num_system_needed // 4
    num_system_system32_needed = num_system_needed // 4
    num_system_syswow64_needed = num_system_needed - (num_system_winsxs_needed + num_system_windows_needed + num_system_system32_needed)
    
    sampled_winsxs = (clean_system_winsxs.sample(n=min(num_system_winsxs_needed, len(clean_system_winsxs)), random_state=42)
                      if num_system_winsxs_needed > 0 else pd.DataFrame())
    sampled_windows = (clean_system_windows.sample(n=min(num_system_windows_needed, len(clean_system_windows)), random_state=42)
                       if num_system_windows_needed > 0 else pd.DataFrame())
    sampled_system32 = (clean_system_system32.sample(n=min(num_system_system32_needed, len(clean_system_system32)), random_state=42)
                        if num_system_system32_needed > 0 else pd.DataFrame())
    sampled_syswow64 = (clean_system_syswow64.sample(n=min(num_system_syswow64_needed, len(clean_system_syswow64)), random_state=42)
                        if num_system_syswow64_needed > 0 else pd.DataFrame())
    sampled_user = (clean_user.sample(n=min(num_user_needed, len(clean_user)), random_state=42)
                    if num_user_needed > 0 else pd.DataFrame())
    
    selected_clean = pd.concat([
        clean_ads,
        sampled_winsxs,
        sampled_windows,
        sampled_system32,
        sampled_syswow64,
        sampled_user
    ], ignore_index=True)
    
    combined_df = pd.concat([malicious_df, selected_clean], ignore_index=True)
    
    # If not enough rows, fill with extra benign rows.
    if len(combined_df) < total_rows:
        extra_needed = total_rows - len(combined_df)
        extra_clean = benign_clean.sample(n=extra_needed, random_state=42, replace=True)
        combined_df = pd.concat([combined_df, extra_clean], ignore_index=True)
    
    combined_df = combined_df.sample(n=total_rows, random_state=42).reset_index(drop=True)
    combined_df.to_csv(output_file, index=False)
    print(f"Combined dataset saved to {output_file} with {len(combined_df)} rows")

def main():
    """
    Main function:
      - Reads benign and malicious file paths from two text files.
      - Processes and combines them into a full dataset (final_full.csv).
      - Creates two additional limited datasets: final_5000.csv and final_10000.csv.
    """
    parser = argparse.ArgumentParser(
        description="Process benign and malicious file paths from text files and output 3 CSV files: final_full.csv, final_5000.csv, and final_10000.csv."
    )
    parser.add_argument("benign_file", type=str, help="Text file containing benign full file paths (one per line).")
    parser.add_argument("malicious_file", type=str, help="Text file containing malicious full file paths (one per line).")
    args = parser.parse_args()

    try:
        with open(args.benign_file, "r") as f:
            benign_paths = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading benign file: {e}")
        return

    try:
        with open(args.malicious_file, "r") as f:
            malicious_paths = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading malicious file: {e}")
        return

    if not benign_paths and not malicious_paths:
        print("No file paths found in either input file.")
        return

    # Process file paths into DataFrames.
    benign_data = populate_columns(benign_paths, is_malicious=0)
    malicious_data = populate_columns(malicious_paths, is_malicious=1)

    # Produce the full combined dataset.
    full_combined = pd.concat([benign_data, malicious_data], ignore_index=True)
    full_combined = deduplicate_data(full_combined)
    full_combined.to_csv("final_full.csv", index=False)
    print(f"Full combined dataset saved to final_full.csv with {len(full_combined)} rows")
    
    # Create limited datasets.
    TOTAL_ROWS_5000 = 5000
    TOTAL_ROWS_10000 = 10000
    combine_limited_datasets(benign_data, malicious_data, "final_5000.csv", TOTAL_ROWS_5000)
    combine_limited_datasets(benign_data, malicious_data, "final_10000.csv", TOTAL_ROWS_10000)

if __name__ == "__main__":
    main()
