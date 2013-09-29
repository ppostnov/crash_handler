import os

system_include  = [os.environ['VCInstallDir']+'include', os.environ['WindowsSdkDir']+'include', 'c:\\Program Files (x86)\\Microsoft SDKs\\Windows\\v7.0A\\Include\\include']
project_include = ['include']

mypath    = [os.environ['SystemRoot']+'\\system32', os.environ['SystemRoot'], os.environ['SystemRoot']+'\\System32\\Wbem', os.environ['VCInstallDir']+'bin\\', os.environ['VSInstallDir']+'Common7\\IDE\\', 'c:\\python27\\', 'c:\\python27\\Scripts\\']
myinclude = system_include + project_include
mylib     = [os.environ['VCInstallDir']+'lib', os.environ['WindowsSdkDir']+'lib', 'c:\\Program Files (x86)\\Microsoft SDKs\\Windows\\v7.0A\\Include\\lib', os.environ['Temp']]

env = Environment(ENV = {'PATH' : mypath, 'INCLUDE' : myinclude, 'LIB' : mylib, 'TMP' : os.environ['TMP']})

# build inner script into build directory
env.SConscript('src/SConscript', exports='env', variant_dir='build', duplicate=0)
