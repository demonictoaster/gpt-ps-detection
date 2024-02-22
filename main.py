import pickle
import random
import re
import time

from openai import OpenAI
import pandas as pd
import tiktoken


random.seed (12)

client = OpenAI()

system_str = """You are a cyber security analyst trying to detect malicious powershell scripts. 
You will give your output in a JSON containing two fields. 
The first field will be called \"outcome\" and can be either \"malicious\" or \"benign\" depending the result of the analysis. 
The second field is called \"assessment\" and contains an explanation of the result. 
This should explain what parts of the powershell scripts are suspicious."""
user_str = "Is the following powershell script malicious or benign:\n{}"

def read_pickle(path: str) -> list:
    with open(path, "rb") as f:
        obj = pickle.load(f)
    return obj

def count_tokens(input_str: str, encoding_name: str) -> int:
    """Count number of token in input string"""
    encoding = tiktoken.get_encoding(encoding_name)
    return len(encoding.encode(input_str))

def get_fields_from_json_str(input_str: str) -> tuple[str]:
    pattern = r'"outcome":\s*"([^"]*)",\s*"assessment":\s*"([^"]*)"'
    match = re.search(pattern, input_str)
    if match:
        outcome = match.group(1)
        assessment = match.group(2)
        return outcome, assessment
    else:
        print("No match found.")

def read_samples(path: str) -> list:
    # samples that are too long need to be filtered out
    # (ChatGPT max context window = 4k tokens)
    samples = read_pickle(path)
    samples = [s for s in samples if count_tokens(s, "cl100k_base") < 38000]
    return samples

def check_samples(samples: list, name: str, true_label: str) -> None:
    results = []
    for sample in samples:
        try:
            completion = client.chat.completions.create(
                model="gpt-3.5-turbo",
                response_format={ "type": "json_object" },
                messages=[
                    {"role": "system", "content": system_str},
                    {"role": "user", "content": user_str.format(sample)}
                ]
            )
            response = completion.choices[0].message 
            try:
                outcome, assessment = get_fields_from_json_str(response.content)
            except:
                outcome = "NOT_PARSED"
                assessment = "NOT_PARSED"
            print(response)
            result = {
                "sample": sample,
                "true_label": true_label,
                "response": response.content,
                "outcome": outcome,
                "assessment": assessment,
            }
            results.append(result)
        except Exception as e:
            print("Error occured: {}".format(e))
        time.sleep(20)

    res_df = pd.DataFrame(results)
    res_df.to_csv("./data/results_{}.csv".format(name), index=False)
    print("All done.")

malicious_samples = read_samples("./data/raw_pure.pkl")
malicious_samples = random.sample(malicious_samples, 180)

benign_samples = read_samples("./data/raw_benign.pkl")
benign_samples = random.sample(benign_samples, 180)

check_samples(malicious_samples, name="pure", true_label="malicious")
check_samples(benign_samples, name="benign", true_label="benign")
