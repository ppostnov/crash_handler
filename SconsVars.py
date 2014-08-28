import os

VCInstallInclude  = ''
WindowsSdkInclude = ''
VCInstallLib  = ''
WindowsSdkLib = ''
VCInstallBin  = ''
VSInstallIDE  = ''

def getEnvVars():
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

getEnvVars()