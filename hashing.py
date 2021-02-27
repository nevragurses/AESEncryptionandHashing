import string
from AES import *

#expanding input with multiple of 32.
def expanding_with_32(content):
    i=0
    addedChar = 97
    while(len(content)%32 != 0 ):
        content += chr(addedChar) #expand operation is doing with adding ASCII string characters.
        if(addedChar == 122):
            addedChar = 97
        addedChar = addedChar + 1
        i+=1
    return content

#for creating hash as 32 character, XOR operation is doing with expanded input.    
def xorOperation(extended):
    hashedMessage=[0]*32
    if(len(extended)!=32):
        #XOR operation with 2 loop. 
        for i in range(len(extended)/32):
            for j in range(32):
                if(i==0):
                    hashedMessage[j]=ord(extended[i*32+j])^ord(extended[(i+1)*32+j])   
                elif(i>=2):
                    hashedMessage[j]=hashedMessage[j]^ord(extended[(i*32)+j]) 
    #If length is 32, this is hash. Convert characters to integer values.                  
    elif(len(extended)==32):
        for i in range(32):
            hashedMessage[i] = ord(extended[i])        
    return hashedMessage

#Hash function. Before, expands the input. After, makes XOR operation.
def hash(intent):
    expanded= expanding_with_32(intent)
    hashedOutput = xorOperation(expanded)
    return hashedOutput

#Encryption of hash with AES.
def cipherwithHash(hashedOutput,key):
    cipherText = [str(i) for i in hashedOutput] 
    cipherText = ' '.join(cipherText ) 
    cipher = encryptOperation(cipherText,"OFB",key)
    return cipher


#Write cipher to the end of the file.
def writeCipher_to_File(file,hashedCipher):
    fileName=open(file,"a")
    cipherText = [str(i) for i in hashedCipher] 
    cipherText = ' '.join(cipherText) 
    fileName.write('\n')
    fileName.write(cipherText)
    fileName.close()
#Function for controlling whether file contents changed or not.
#For controlling; decrtyption operation does for cipher in file, and also getting hash again file content.
#if this 2 result are equal, file does not changed, else file was changed.
def controlChanging(file,key):
    fileName=open(file,"r")
    Lines = fileName.readlines()
    cipherLine = Lines[-1]

    #convert integer array to string.    
    cipherList = cipherLine.split(" ")
    cipherMessage= ""
    for i in range(0,len(cipherList)):
        cipherMessage+= chr(int(cipherList[i]))

    decryipted = decryptOperation(key,cipherMessage,"OFB") #decryption operation is doing.
   #getting file contents.
    Lines =Lines[:-1]
    clearText = ""
    count = 0
    newLastLine=Lines[-1]
    newLastLine = Lines[-1]
    for line in Lines: 
        clearText += line.strip()
        if(line!= newLastLine):
            clearText += '\n'
        count+=1
 
    hashedOutput= hash(clearText) #hashing file contents.
    hashed = [str(i) for i in hashedOutput] 
    hashed  = ' '.join(hashed) 
    fileName.close()
    size = len(hashedOutput)
    #Controlling whether 2 hash equal or not.
    for i in range(size):
        if  decryipted[i]!=hashed[i]:
            return True
    return False

#Changing the file for testing.
def changeFile_forTesting(fileName):
    file=open(fileName,"r") 
    fline="Dosya degistiriliyor.\n"   
    read_line=file.readlines() 
    read_line.insert(0,fline) 
    file.close() 
    file=open(fileName,"w") 
    file.writelines(read_line) 
    file.close() 
#main    
if __name__ == "__main__":

    #Testing that is file does not changed.
    print '\n~~~~~~TEST - 1:~~~~~~~~'
    file="testFile.txt"
    key = generate_Random_Key(32);
    print '\nAnahtar: ', [ord(x) for x in key]
    fileName=open(file,"r")
    content = fileName.read()
    hashedOutput= hash(content)
    print '\nOzut Metin: ',hashedOutput
    fileName.close()
    cipher=cipherwithHash (hashedOutput,key)
    print '\nSifrelenmis Metin: ',cipher
    writeCipher_to_File(file,cipher)
    result = controlChanging(file,key)
    print '\nDosya Kontrolu: ' , result
    if(result == True):
        print 'Sonuc: true, dosya degistirildi.'
    if(result == False):
        print 'Sonuc: false, dosya degistirilmedi.'
    
    #Testing that is file changed.
    print '\n~~~~~~TEST - 2:~~~~~~~~'
    fileName=open(file,"r")
    content = fileName.read()
    key = generate_Random_Key(32);
    print '\nAnahtar: ', [ord(x) for x in key]
    hashedOutput= hash(content)
    print '\nOzut Metin: ',hashedOutput
    fileName.close()
    cipher=cipherwithHash (hashedOutput,key)
    print '\nSifrelenmis Metin: ',cipher
    writeCipher_to_File(file,cipher)
    changeFile_forTesting(file)
    result = controlChanging(file,key)
    print '\nDosya Kontrolu: ' , result
    if(result == True):
        print 'Sonuc: true, dosya degistirildi.'
    if(result == False):
        print 'Sonuc: false, dosya degistirilmedi.'
    