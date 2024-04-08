# Morion
**Morion** is a *proof-of-concept (PoC)* tool to experiment with **symbolic execution** and to
research current limitations that this technique has when it comes to **real-world binaries**.
*Morion* relies on [Triton](https://triton-library.github.io/) as its underlying symbolic execution
engine and (currently) has the following features / limitations:
- **Record** concrete execution traces of a target binary (potentially in cross-platform remote setups)
  - Record initial context (concrete initial values of all registers / memory cells accessed during the trace)
  - Record sequence of assembly instructions (executed by the trace)
  - Hooking / skipping of instruction sequences or functions
- **Analyze** collected program traces by executing them symbolically
  - Symbolic function modeling
  - Different analysis passes
    - Calculating backward slices
    - Detecting control-flow / memory hijacking conditions
    - Reasoning about code coverage (branches / paths)
    - Assisting during ROP chains generation
- *Morion* is currently limited to binaries of the **ARMv7** architecture

The following figure provides a high-level overview about *Morion* and its two modes of operation -
**tracing** and **symbolic execution**:

<figure>
  <img src="./images/Morion_Overview.svg" alt="Morion Overview"/>
</figure>

## Installation
Note: The following installation instructions have only been tested on Ubuntu 20.04/22.04 LTS.
### Triton
#### Dependencies
```shell
# build tools, libboost, libpython and libz3
sudo apt install cmake gcc g++ libboost-all-dev libpython3-dev libz3-dev

# libcapstone
curl -L https://github.com/capstone-engine/capstone/archive/refs/tags/5.0.1.tar.gz -o capstone.tar.gz
tar -xvzf capstone.tar.gz && rm capstone.tar.gz
mv capstone-5.0.1 capstone && cd capstone/
./make.sh
sudo ./make.sh install
cd ../
```
#### LibTriton
```shell
git clone https://github.com/JonathanSalwan/Triton && cd Triton/
mkdir build && cd build/
cmake ..
make -j4
sudo make install
cd ../../
```
**Note**: The *Triton* library is put into `/usr/local/lib/python3.X/site-packages/`, which is the
default location for non-Debian Python packages built from source. Debian-based systems by default
put Python packages built from source into `/usr/local/lib/python3.X/dist-packages`. To cope with
this, you might create the following link on Debian-based systems (here for Python version 3.10):
```shell
sudo ln -s\
  /usr/local/lib/python3.10/site-packages/triton.so \
  /usr/local/lib/python3.10/dist-packages/triton.so
```
### Morion
#### Dependencies
```shell
# GNU project debugger (for tracing)
sudo apt install gdb gdb-multiarch
```
#### Morion
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
      paths = subprocess.check_output('python -c "import os, sys;print(os.linesep.join(sys.path).strip())"', shell=True).decode("utf-8").split()
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
    pip install .
    ```
## Usage
### Tracing
Tracing with GDB (or GDB-Multiarch):
```shell
gdb -q -x morion/tracing/gdb/trace.py
(gdb) morion_trace                    # Show usage
(gdb) help target                     # Attach to target binary
```
The `.gdbinit` file can be updated to automatically register Morion's tracing command at each launch of GDB:
```shell
cat << EOF >> ~/.gdbinit
# Register Morion's trace command 'morion_trace' with GDB 
source $PWD/tracing/gdb/trace.py
EOF
```
### Symbolic Execution
Symbolic execution of a binary's program trace:
```shell
morion                  -h  # Perform symbolic execution
morion_pwndbg           -h  # Use morion alongside pwndbg
morion_control_hijacker -h  # Use symbolic execution to identify potential control flow hijacks
morion_memory_hijacker  -h  # Use symbolic execution to identify potential memory hijacks
morion_branch_analyzer  -h  # Use symbolic execution to analyze branches
morion_path_analyzer    -h  # Use symbolic execution to analyze paths
morion_backward_slicer  -h  # Use symbolic execution to calculate backward slices
morion_rop_generator    -h  # Use symbolic execution to generate a ROP chain
```
