import os

system_include  = []

VCInstallInclude  = ''
WindowsSdkInclude = ''
VCInstallLib  = ''
WindowsSdkLib = ''
VCInstallBin  = ''
VSInstallIDE  = ''

VCInstallDir = os.getenv('VCInstallDir')
if VCInstallDir is not None:
    if not VCInstallDir.endswith('\\'):
        VCInstallDir += '\\'
    VCInstallInclude = VCInstallDir + 'include\\'
    VCInstallLib     = VCInstallDir + 'lib\\'
    VCInstallLib     = VCInstallDir + 'bin\\'

WindowsSdkDir = os.getenv('WindowsSdkDir')
if WindowsSdkDir is not None:
    if not WindowsSdkDir.endswith('\\'):
        WindowsSdkDir += '\\'
    WindowsSdkInclude = WindowsSdkDir + 'Include\\'
    WindowsSdkLib     = WindowsSdkDir + 'lib\\'

VSInstallDir = os.getenv('VSInstallDir')
if VSInstallDir is not None:
    if not VSInstallDir.endswith('\\'):
        VSInstallDir += '\\'
    VSInstallIDE = VSInstallDir + 'Common7\\IDE\\'
        
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
