# Update GDB's Python paths with the ones from the local Python installation (e.g. to support virtual environments)
python
import os, subprocess, sys
paths = subprocess.check_output('python -c "import os, sys;print(os.linesep.join(sys.path).strip())"', shell=True).decode("utf-8").split()
sys.path.extend(paths)
end