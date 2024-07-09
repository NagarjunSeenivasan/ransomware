
import glob
path="D:/soft"

print('\nNamed with wildcard *:')
for files in glob.glob(path + '*'):
    print(files)
 
# Using '?' pattern
print('\nNamed with wildcard ?:')
for files in glob.glob(path + '?.txt'):
    print(files)
 
 
# Using [0-9] pattern
print('\nNamed with wildcard ranges:')
for files in glob.glob(path + '/*[0-9].*'):
    print(files)
