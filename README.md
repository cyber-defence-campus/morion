# Morion
<!--TODO--------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------->

<p align="center">
  <img src="./images/Morion_Logo.svg" alt="Morion Logo"/>
</p>

**Morion** is a *proof-of-concept (PoC)* tool to experiment with **symbolic execution** and to
research current limitations that this technique has when it comes to **real-world binaries**.
*Morion* relies on [Triton](https://triton-library.github.io/) as its underlying symbolic execution
engine and (currently) has the following features / limitations:
- **Record** concrete execution traces of a target binary (optionally in cross-platform remote setups)
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

**Disclaimer**: TODO

## Installation
**Note**: The following installation instructions have only been tested on Ubuntu 20.04/22.04 LTS.
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
### Morion
#### Dependencies
```shell
# GNU project debugger (for tracing)
sudo apt install gdb gdb-multiarch
```
#### Morion
1. Clone the repository:
    ```shell
    git clone https://github.com/cyber-defence-campus/morion.git && cd morion/
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
    - Create and activate a virtual environment with added Triton Python bindings (here for Python version 3.10):
      ```shell
      python3 -m venv venvs/morion
      cp /usr/local/lib/python3.10/site-packages/triton.so venvs/morion/lib/python3.10/site-packages/triton.so
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
### Example
- [Exploiting a Stack Buffer Overflow on the NETGEAR R6700v3 (CVE-2022-27646) with the Help of Symbolic Execution](https://github.com/cyber-defence-campus/netgear_r6700v3_circled)
## Authors
- [Damian Pfammatter](https://github.com/pdamian), [Cyber-Defense Campus (armasuisse S+T)](https://www.cydcampus.admin.ch/)
