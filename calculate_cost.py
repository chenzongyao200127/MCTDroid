import os
from collections import defaultdict
from statistics import mean
from pathlib import Path

def process_efficiency_file(file_path):
    """Process a single efficiency.txt file and return queries and time"""
    try:
        with open(file_path) as f:
            lines = f.readlines()
            if len(lines) >= 2:
                queries = int(lines[0].strip())
                time = float(lines[1].strip().rstrip('%'))
                return queries, time
    except (ValueError, IOError) as e:
        print(f"Error processing {file_path}: {e}")
    return None

def calculate_directory_averages(base_path):
    """Calculate average queries and times for all directories"""
    base_path = Path(base_path)
    results = defaultdict(lambda: {'queries': [], 'times': []})
    
    # Collect all data points
    for efficiency_file in base_path.rglob('efficiency.txt'):
        target_dir = efficiency_file.parts[len(base_path.parts)]
        data = process_efficiency_file(efficiency_file)
        if data:
            queries, time = data
            results[target_dir]['queries'].append(queries)
            results[target_dir]['times'].append(time)

    # Calculate averages
    averages = {
        dir_name: (
            mean(data['queries']) if data['queries'] else 0,
            mean(data['times']) if data['times'] else 0
        )
        for dir_name, data in results.items()
    }
    
    return averages

def print_results(averages):
    """Print results in a formatted table"""
    headers = ("Directory", "Average Queries", "Average Attack Time (s)")
    format_str = "{:<20} {:<30} {:<30}"
    
    print(format_str.format(*headers))
    for dir_name, (avg_queries, avg_time) in sorted(averages.items()):
        print(format_str.format(dir_name, avg_queries, avg_time))

def main():
    base_path = '/disk2/chenzy/MCTDroid/results/Androzoo/mamadroid_rf'
    averages = calculate_directory_averages(base_path)
    print_results(averages)

if __name__ == '__main__':
    main()
