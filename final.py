import vt
import pandas as pd
from openpyxl import load_workbook
import time

VT_API_KEY = " "  # Replace with your actual API key

# Load the CSV file containing hash values
csv_file = "hashes.xlsx"

# Function to validate hash format
def is_valid_hash(file_hash):
    return len(file_hash) in [32, 40, 64]

# Function to read hash list from the CSV
def read_hashes(file_name):
    try:
        df = pd.read_excel(file_name)  # Load Excel file
        hashes = df.iloc[3:, 2].dropna().astype(str).tolist()  # Extract valid hashes from column 2
        return [h for h in hashes if is_valid_hash(h)]  # Validate hash format
    except FileNotFoundError:
        print(f"Error: File '{file_name}' not found.")
        return []
    except Exception as e:
        print(f"Error Reading Hash: {e}")
        return []

# Read hashes from CSV
hash_list = read_hashes(csv_file)

# Store VirusTotal results
analysis_results = []

# Using VirusTotal API
with vt.Client(VT_API_KEY) as vt_client:
    for index, file_hash in enumerate(hash_list, start=2):
        print(f"Analyzing hash: {file_hash}")

        try:
            vt_data = vt_client.get_object(f"/files/{file_hash}")
            detection_count = vt_data.last_analysis_stats.get("malicious", 0)

            creation_time = getattr(vt_data, "creation_date", "unknown")
            signature_date = getattr(vt_data, "signature_date", "unknown")
            first_seen = getattr(vt_data, "first_seen_itw_date", "unknown")  # First Seen In The Wild
            names = vt_data.names if hasattr(vt_data, "names") else []
            name1, name2, name3 = (names + ["null", "null", "null"])[:3]  # Fill missing names

            # Store Analysis Data 
            result_entry = {
                "hash": file_hash,
                "detection_count": detection_count,
                "hash_md5": vt_data.md5,
                "hash_sha1": vt_data.sha1,
                "hash_sha256": vt_data.sha256,
                "file_type": vt_data.type_description,
                "file_magic": vt_data.magic,
                "file_creation_time": creation_time,
                "signature_date": signature_date,
                "first_seen_wild": first_seen,
                "first_submission_date": vt_data.first_submission_date,
                "last_submission_date": vt_data.last_submission_date,
                "last_analysis_date": vt_data.last_analysis_date,
                "file_name_1": name1,
                "file_name_2": name2,
                "file_name_3": name3,
                "final_verdict": "Malicious" if detection_count > 0 else "Benign",
            }

        except vt.error.APIError as api_err:
            print(f"Error fetching data for {file_hash}: {api_err}")
            result_entry = {"hash": file_hash, "detection_count": "unknown"}

        except Exception as e:
            print(f"Unexpected error: {e}")
            result_entry = {"hash": file_hash, "detection_count": "unknown"}

        # Store results 
        analysis_results.append(result_entry)

        if index % 2 == 0 or index == len(hash_list):
            df = pd.DataFrame(analysis_results)
            df.to_excel("Results.xlsx", index=False)
            print(f"Saved progress to Results.xlsx")

        # Display progress and add delay for API rate limits
        print(f"Parsing hash number {index}: {file_hash}")
        time.sleep(15)  # Adjust 15 for API rate limits

# Print results 
print("\nFinal results saved to Results.xlsx")
