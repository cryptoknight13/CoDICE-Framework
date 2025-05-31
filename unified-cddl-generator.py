import os
import pathlib
import sys

def process_files(directory):
    # Path to auto-gen.cddl file
    auto_gen_file = os.path.join(directory, "auto-gen.cddl")
    
    
    with open(auto_gen_file, 'w') as auto_gen_file:
        # Add root.cddl at the top.
        with open("root.cddl", 'r') as f:
            auto_gen_file.write(f.read() + "\n \n")

        # Iterate over the files in the directory
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            
            # Check if the file has a .cddl extension
            if os.path.isfile(file_path) and filename.endswith(".cddl"):

                # Open the .cddl file and read its content
                # Skip ami-manifest.cddl as it was already added.
                with open(file_path, 'r') as f:
                    if "root.cddl" in filename:
                        continue
                    content = f.read()
                
                # Append the content of the .cddl file to auto-gen.cddl
                auto_gen_file.write(content + "\n \n")  # Append the content with a newline after
        

if __name__ == "__main__":
    if (len(sys.argv)) <= 1:
        print("Please give path to the cddl files as an commandline argument")
        exit()

    path = str(pathlib.Path(__file__).parent.resolve().cwd()) + '/' + sys.argv[1]



os.chdir(path)
process_files(path)
