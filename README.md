# Morion
## Installation
### Triton
#### Dependencies
```shell
# libcapstone
curl -L https://github.com/capstone-engine/capstone/archive/refs/tags/4.0.2.tar.gz -o capstone.tar.gz
tar -xvzf capstone.tar.gz && rm capstone.tar.gz
mv capstone-4.0.2 Capstone && cd Capstone/
./make.sh
sudo ./make.sh install

# libboost, libpython and libz3
sudo apt install libboost-all-dev libpython3-dev libz3-dev
```
#### LibTriton
```shell
git clone https://github.com/JonathanSalwan/Triton && cd Triton/
mkdir build && cd build/
cmake ..
make -j4
sudo make install
```
Note: The Triton library is put into `/usr/local/lib/python3.X/site-packages/`, which is the default location for non-Debian Python packages built from source. Debian-based systems by default put Python packages built from source into `/usr/local/lib/python3.X/dist-packages`. To cope with this, you might create the following link on Debian-based systems (here for Python version 3.10):
```shell
sudo ln -s\
  /usr/local/lib/python3.10/site-packages/triton.so \
  /usr/local/lib/python3.10/dist-packages/triton.so
```
### Morion
1. Clone the repository:
```shell
git clone https://github.com/pdamian/morion.git && cd morion/
```
2. Use a Python virtual enviroment (optional, but recommended):
   - GDB uses the system-installed Python interpreter and the corresponding site-packages, even when using a Python virtual environment. In order to fix that, add the following to your `.gdbinit` file:    
```shell
cat << EOF >> ~/.gdbinit

# Update GDB's Python paths with the ones from the local Python installation (e.g. to support virtual environments)
python
import os, subprocess, sys
paths = subprocess.check_output('python -c "import os,sys;print(os.linesep.join(sys.path).strip())"',shell=True).decode("utf-8").split()
sys.path.extend(paths)
end
EOF
```
   - Create a virtual environment (with access to the system's site-packages to reach the Triton Python bindings)
```shell
python3 -mvenv venvs/morion --system-site-packages
source venvs/morion/bin/activate
```
3. Install the package (add `-e` for editable mode):
```shell
(morion) pip install .
```
## Usage
### Tracing
Tracing with GDB (or GDB-Multiarch):
```shell
gdb -q -x morion/tracing/gdb/trace.py
(gdb) morion_trace                    # Show usage
(gdb) help target                     # Attach to target binary
```
### Symbolic Execution
Symbolic execution of a binary's program trace:
```shell
(morion) morion -h                   # Perform symbolic execution
(morion) morion_backward_slicer  -h  # Use symbolic execution to calculate backward slices
(morion) morion_control_hijacker -h  # Use symbolic execution to identify potential control flow hijacks
(morion) morion_memory_hijacker  -h  # Use symbolic execution to identify potential memory hijacks
(morion) morion_branch_analyzer  -h  # Use symbolic execution to analyze branches
(morion) morion_path_analyzer    -h  # Use symbolic execution to analyze paths
```
