import psutil
def checkIfProcessRunning(processName):
    '''
    Check if there is any running process that contains the given name processName.
    '''
    #Iterate over the all the running process
    for proc in psutil.process_iter():
        try:
            # Check if process name contains the given name string.
            if processName.lower() in proc.name().lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False;



# Check if any chrome process was running or not.
if checkIfProcessRunning('WampServer2.0c.exe'):
    print('Exe file was running')
else:
    print('No Exe was running')
