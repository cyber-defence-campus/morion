# Morion
## Installation
### Triton
#### Dependencies
```shell
# libcapstone
git clone https://github.com/capstone-engine/capstone && cd capstone/
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
Note: The Triton library is put into `/usr/local/lib/python3.X/site-packages/`, which is the default location for non-Debian Python packages built from source. Debian-based systems by default put Python packages built from source into `/usr/local/lib/python3.X/dist-packages`. To cope with this, you might create the following link on Debian-based systems (here for Python version 3.8):
```shell
sudo ln -s\
  /usr/local/lib/python3.8/site-packages/triton.so \
  /usr/local/lib/python3.8/dist-packages/triton.so
```
### Morion
1. Clone the repository:
```shell
git clone https://github.com/pdamian/morion.git && cd morion/
```
2. Optional (but recommended):
- Update GDB's Python paths with the ones from the local Python installation
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
(concolex) pip install .
```
4. Tracing with GDB (or GDB-Multiarch):
```shell
gdb -q -x morion/tracing/gdb/trace.py
(gdb) trace         # Show usage
(gdb) help target   # Attach to target binary
```
