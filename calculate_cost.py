import os

# Set the base directory where all the target directories are located
base_path = '/disk2/chenzy/MCTDroid/results/Androzoo/mamadroid_rf'

# Prepare to collect average queries and times for each directory
averages = {}

# Loop through each target directory in the base directory
for target_dir in os.listdir(base_path):
    # Construct the full path to the target directory
    full_path = os.path.join(base_path, target_dir)

    # Check if it's a directory
    if os.path.isdir(full_path):
        # Initialize variables for this directory
        total_queries = 0
        total_time = 0
        file_count = 0

        # Walk through the directory structure
        for root, dirs, files in os.walk(full_path):
            for file in files:
                if file == 'efficiency.txt':
                    # Construct the full file path
                    file_path = os.path.join(root, file)
                    # Open and read the file
                    with open(file_path, 'r') as f:
                        lines = f.readlines()

                        # Ensure there are at least two lines
                        if len(lines) >= 2:
                            queries_line = lines[0].strip()
                            time_line = lines[1].strip().rstrip('%')

                            try:
                                queries = int(queries_line)
                                time = float(time_line)
                                total_queries += queries
                                total_time += time
                                file_count += 1
                            except ValueError as e:
                                print(
                                    f"Error processing file {file_path}: {e}")

        # Calculate averages for this directory
        if file_count > 0:
            average_queries = total_queries / file_count
            average_time = total_time / file_count
            averages[target_dir] = (average_queries, average_time)
        else:
            print(
                f"No 'efficiency.txt' files found in {target_dir} or valid lines to read.")

# Print out the averages for each directory with improved formatting
print("{:<20} {:<30} {:<30}".format("Directory",
      "Average Queries", "Average Attack Time (s)"))
for target_dir, (avg_queries, avg_time) in sorted(averages.items()):
    print("{:<20} {:<30} {:<30}".format(target_dir, avg_queries, avg_time))
