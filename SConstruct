import os
import SconsVars

from SconsVars import *


system_include  = []

osystem_include = [VCInstallInclude, WindowsSdkInclude]

project_include = ['#include']

mypath = [os.environ['SystemRoot']+'\\system32', os.environ['SystemRoot'], os.environ['SystemRoot']+'\\System32\\Wbem', VCInstallBin, VSInstallIDE, 'c:\\python27\\', 'c:\\python27\\Scripts\\']
mylib  = [VCInstallLib, WindowsSdkLib, os.environ['Temp']]

env = Environment(ENV = {'PATH' : mypath, 'INCLUDE' : system_include, 'LIB' : mylib, 'TMP' : os.environ['TMP']},
CPPPATH = project_include,
CPPFLAGS = ['/EHsc'])
print '+++++++++++++++++++++++++++++++++++'
for k, v in env['ENV'].items():
    print k, ':', v
print '+++++++++++++++++++++++++++++++++++'

# build inner script into build directory
env.SConscript('src/SConscript', exports='env', variant_dir='build', duplicate=0)
