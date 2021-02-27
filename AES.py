import math
import os
import sys

#Class that does AES operations.
class AES(object):
    #Rijndael S-box. This is created with GF(2^8)
    s_box =  [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
            0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
            0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
            0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
            0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
            0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
            0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
            0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
            0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
            0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
            0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
            0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
            0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
            0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
            0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
            0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
            0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
            0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
            0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
            0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
            0x54, 0xbb, 0x16]

    #Rijndael inverted S-box
    rsbox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
            0x9e, 0x81, 0xf3, 0xd7, 0xfb , 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
            0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb , 0x54,
            0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
            0x42, 0xfa, 0xc3, 0x4e , 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
            0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 , 0x72, 0xf8,
            0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
            0x65, 0xb6, 0x92 , 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
            0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 , 0x90, 0xd8, 0xab,
            0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
            0x45, 0x06 , 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
            0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b , 0x3a, 0x91, 0x11, 0x41,
            0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
            0x73 , 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
            0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e , 0x47, 0xf1, 0x1a, 0x71, 0x1d,
            0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
            0xfe, 0x78, 0xcd, 0x5a, 0xf4 , 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
            0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f , 0x60,
            0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
            0x93, 0xc9, 0x9c, 0xef , 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
            0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 , 0x17, 0x2b,
            0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
            0x21, 0x0c, 0x7d]
   
    # Rijndael Rcon
    Rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
            0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
            0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
            0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
            0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
            0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61,
            0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
            0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
            0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
            0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
            0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4,
            0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08,
            0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
            0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
            0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74,
            0xe8, 0xcb ]

    # key sizes.        
    size_of_key = dict(SIZE_128=16, SIZE_192=24, SIZE_256=32)   

    #Getting given SBox value.
    def getting_SBox(self,number):
        return self.s_box[number]

   

    #key expansion of Rinjdael.
    def expandKey(self, key, size, expanded_Key_Size):
        currentSize = 0
        iteration_rron= 1
        expandedKey = [0] * expanded_Key_Size

        # setting the bytes that are 16, 24, 32 of the expanded key to the input key.
        for j in range(size):
            expandedKey[j] = key[j]
        currentSize += size

        while currentSize < expanded_Key_Size:
            temp = expandedKey[currentSize-4:currentSize]     #assigning the previous 4 bytes to the temporary value.

            # Each  bytes applying the key schedule to temp and increment iteration.
            if currentSize % size == 0:
                temp = self.keyScheduling(temp, iteration_rron)
                iteration_rron += 1
            #For 256-bit keys,add an extra Sbox.
            if size == self.size_of_key["SIZE_256"] and ((currentSize % size) == 16):
                for l in range(4): temp[l] = self.getting_SBox(temp[l])

            #XOR temp with the four-byte block 16,24,32 bytes before the new expanded key. 
            for m in range(4):
                expandedKey[currentSize] = expandedKey[currentSize - size] ^ \
                        temp[m]
                currentSize += 1

        return expandedKey

    #Getting given inverted SBox value.
    def getting_SBox_Invert(self,number):
        return self.rsbox[number]

    #Getting given Rcon value.
    def getting_Rcon(self, number):
        return self.Rcon[number]

    #key schedule rotate operation of Rijndael.
    def rotation(self, word):
        return word[1:] + word[:1]

    #Key scheduling  method.
    def keyScheduling(self, word, iteration):
        word = self.rotation(word)  # rotation the 32-bit word 8 bits to the left.
        # applying S-Box substitution.
        for i in range(4):
            word[i] = self.getting_SBox(word[i])
        word[0] = word[0] ^ self.getting_Rcon(iteration) # XOR the output of the rcon operation.
        return word
   
    #Galois multiplication of 8 bit characters a and b.
    def galois_multiplication(self, a, b):
        p = 0
        i=0
        while (i<8):
            if b & 1: p ^= a
            set_of_bit = a & 0x80
            a <<= 1
            # keeping a 8 bit
            a &= 0xFF
            if set_of_bit:
                a ^= 0x1b
            b >>= 1
            i=i+1
        return p

    # Substitutiton of all the values from the state with the value in the SBox using the state value as index for the SBox.
    def byte_substitution(self,  situation, inverse):
        if inverse: 
            getter = self.getting_SBox_Invert
        else: 
            getter = self.getting_SBox
        i=0
        while(i<16):
            situation[i] = getter( situation[i])
            i=i+1
        return situation

    
    #One Shifting row operation.Calling in every iteration shifts the row to the left by one.
    def shift_Row(self,  situation, pointer_table, number, inverse):
        i=0;
        while(i<number):
            if inverse:
                situation[pointer_table:pointer_table+4] = \
                        situation[pointer_table+3:pointer_table+4] + \
                        situation[pointer_table:pointer_table+3]
            else:
                situation[pointer_table:pointer_table+4] = \
                        situation[pointer_table+1:pointer_table+4] + \
                        situation[pointer_table:pointer_table+1]
            i=i+1            
        return  situation

    # Shifting rows with four iteration.
    def shift_Rows(self, situation,is_inverse):
        i=0
        while(i<4):
            situation = self.shift_Row( situation, i*4, i, is_inverse)
            i=i+1
        return situation
        
    # Galois multiplication of 1 column of the 4x4 matrix.
    def mixColumn(self, column, isInv):
        if isInv: 
            mult = [14, 9, 13, 11]
        else: 
            mult = [2, 1, 1, 3]
        keep_column = list(column)
        g = self.galois_multiplication

        column[0] = g(keep_column[0], mult[0]) ^ g(keep_column[3], mult[1]) ^ \
                    g(keep_column[2], mult[2]) ^ g(keep_column[1], mult[3])
        column[1] = g(keep_column[1], mult[0]) ^ g(keep_column[0], mult[1]) ^ \
                    g(keep_column[3], mult[2]) ^ g(keep_column[2], mult[3])
        column[2] = g(keep_column[2], mult[0]) ^ g(keep_column[1], mult[1]) ^ \
                    g(keep_column[0], mult[2]) ^ g(keep_column[3], mult[3])
        column[3] = g(keep_column[3], mult[0]) ^ g(keep_column[2], mult[1]) ^ \
                    g(keep_column[1], mult[2]) ^ g(keep_column[0], mult[3])
        return column
    # Mix colum operation.Actually this operation is matrix multiplication in GF(2^8)
    def mix_Columns(self, state, is_inverse):
        i=0
        #loop over four column.
        while(i<4):
            column = state[i:i+16:4]
            column = self.mixColumn(column, is_inverse)  # applying the mixColumn on one column.
            state[i:i+16:4] = column  
            i=i+1
        return state


    #Creation of round key. This key created from given expanded key and position.
    def create_round_key(self, expandedKey, roundKey_Pointer):
        round_Key = [0] * 16
        for i in range(4):
            for j in range(4):
                round_Key[j*4+i] = expandedKey[roundKey_Pointer + i*4 + j]
        return round_Key

    #For the state, this method XOR's the round key.
    def add_round_key(self, state, roundKey):
        i=0;
        while(i<16):
            state[i] ^= roundKey[i]
            i=i+1
        return state

    # Appling the four operation for AES round
    def round_of_AES(self, state, roundKey):
        state = self.byte_substitution(state, False)
        state = self.shift_Rows(state, False)
        state = self.mix_Columns(state, False)
        state = self.add_round_key(state, roundKey)
        return state

    
    # Perform the AES steps.
    def AES_operation(self, state, expandedKey, nbrRounds):
        state = self.add_round_key(state, self.create_round_key(expandedKey, 0))
        i = 1
        while i < nbrRounds:
            state = self.round_of_AES(state,self.create_round_key(expandedKey, 16*i))
            i += 1
        state = self.byte_substitution(state, False)
        state = self.shift_Rows(state, False)
        state = self.add_round_key(state,self.create_round_key(expandedKey, 16*nbrRounds))
        return state

    # appling the 4 operations of the inverse round.
    def AES_inverse_round(self, state, roundKey):
        state = self.shift_Rows(state, True)
        state = self.byte_substitution(state, True)
        state = self.add_round_key(state, roundKey)
        state = self.mix_Columns(state, True)
        return state

    # Perform the inverse AES.
    def AES_inverse_operation(self, state, expandedKey, nbrRounds):
        state = self.add_round_key(state,self.create_round_key(expandedKey, 16*nbrRounds))
        i = nbrRounds - 1
        while i > 0:
            state = self.AES_inverse_round(state,self.create_round_key(expandedKey, 16*i))
            i -= 1
        state = self.shift_Rows(state, True)
        state = self.byte_substitution(state, True)
        state = self.add_round_key(state, self.create_round_key(expandedKey, 0))
        return state

    # Encyription a 128 bit input block with given key size.
    def encrypt(self, message_input, key, size):
        numberofRounds = 0 
        block = [0] * 16 
        output = [0] * 16 
        # setting the number of rounds.
        if size == self.size_of_key["SIZE_128"]: 
            numberofRounds = 10
        elif size == self.size_of_key["SIZE_192"]: 
            numberofRounds = 12
        elif size == self.size_of_key["SIZE_256"]: 
            numberofRounds = 14
        else: return None

        expandedKeySize = 16*(numberofRounds+1)  # expanded key size

        # iterate over the columns and rows
        for i in range(4):
            for j in range(4):
                block[(i+(j*4))] = message_input[(i*4)+j]

        expandedKey = self.expandKey(key, size, expandedKeySize)    #expanded key
        block = self.AES_operation(block, expandedKey, numberofRounds)   # encrypt the block using the expandedKey

        # unmapping the block again into the output.
        for k in range(4):
            for l in range(4):
                output[(k*4)+l] = block[(k+(l*4))]

        return output

    # Decription a 128 bit input block with given key size.
    def decrypt(self, message_input, key, size):
        numberofRounds = 0 
        block = [0] * 16   
        output = [0] * 16
        # setting the number of rounds
        if size == self.size_of_key["SIZE_128"]:  
            numberofRounds = 10
        elif size == self.size_of_key["SIZE_192"]:  
            numberofRounds = 12
        elif size == self.size_of_key["SIZE_256"]:  
            numberofRounds = 14
        else: return None

        expandedKeySize = 16*( numberofRounds+1)   #expanded key size

        # iteration over the columns and rows.
        for i in range(4):
            for j in range(4):
                block[(i+(j*4))] = message_input[(i*4)+j]
    
        expandedKey = self.expandKey(key, size, expandedKeySize) #expanded key.
        block = self.AES_inverse_operation(block, expandedKey,  numberofRounds)    # decryption of the block using the expandedKey.
        # unmapping the block again into the output.
        for k in range(4):
            for l in range(4):
                output[(k*4)+l] = block[(k+(l*4))]
        return output

#Operates CBC and OFB modes with AES.
class AES_Mode_Operation(object):
    aes = AES()
    modeOfOperation = dict(OFB=0,CBC=1)

    # converting a 16 character string into a number array.
    def convertString(self, string, start, end, mode):
        if end - start > 16: 
            end = start + 16
        if mode == self.modeOfOperation["CBC"]: 
            array = [0] * 16
        else: array = []

        j = 0
        i = start
        while len(array) < end - start:
            array.append(0)
        while i < end:
            array[j] = ord(string[i])
            i += 1
            j += 1
        
        return array

    # Encryption operation using Mode.
    def encrypt(self, cleartext, mode, key, size, initialVector):
        if len(initialVector) % 16:
            return None
        if len(key) % size:
            return None
       
        plaintext = []
        output = []
        text_input = [0] * 16
        ciphertext = [0] * 16
        cipherOut = []
        firstRound = True
        if cleartext != None:
            for j in range(int(math.ceil(float(len(cleartext))/16))):
                start = j*16
                end = j*16+16
                if  end > len(cleartext):
                    end = len(cleartext)
                plaintext = self.convertString(cleartext, start, end, mode)
                if mode == self.modeOfOperation["CBC"]:
                    for i in range(16):
                        if firstRound:
                            text_input[i] =  plaintext[i] ^ initialVector[i]
                        else:
                            text_input[i] =  plaintext[i] ^ ciphertext[i]
                    firstRound = False
                    ciphertext = self.aes.encrypt(text_input, key, size)
                    for k in range(16):
                        cipherOut.append(ciphertext[k])
                elif mode == self.modeOfOperation["OFB"]:
                    if firstRound:
                        output = self.aes.encrypt( initialVector, key, size)
                        firstRound = False
                    else:
                        output = self.aes.encrypt(text_input, key, size)
                    for i in range(16):
                        if len(plaintext)-1 < i:
                            ciphertext[i] = 0 ^ output[i]
                        elif len(output)-1 < i:
                            ciphertext[i] = plaintext[i] ^ 0
                        elif len(plaintext)-1 < i and len(output) < i:
                            ciphertext[i] = 0 ^ 0
                        else:
                            ciphertext[i] = plaintext[i] ^ output[i]
                    for k in range(end-start):
                        cipherOut.append(ciphertext[k])
                    text_input = output
                
        return mode, len(cleartext), cipherOut

    # Decryription operation with mode.
    def decrypt(self, cipherIn, originalsize, mode, key, size, initialVector):
        if len(initialVector) % 16:
            return None
        if len(key) % size:
            return None
    
        ciphertext = []
        text_input = []
        output = []
        out = []
        plaintext = [0] * 16
        firstRound = True
        if cipherIn != None:
            for j in range(int(math.ceil(float(len(cipherIn))/16))):
                start = j*16
                end = j*16+16
                if j*16+16 > len(cipherIn):
                    end = len(cipherIn)
                ciphertext = cipherIn[start:end]
                if mode == self.modeOfOperation["OFB"]:
                    if firstRound:
                        output = self.aes.encrypt(initialVector, key, size)
                        firstRound = False
                    else:
                        output = self.aes.encrypt(text_input, key, size)
                    for i in range(16):
                        if len(output)-1 < i:
                            plaintext[i] = 0 ^ ciphertext[i]
                        elif len(ciphertext)-1 < i:
                            plaintext[i] = output[i] ^ 0
                        elif len(output)-1 < i and len(ciphertext) < i:
                            plaintext[i] = 0 ^ 0
                        else:
                            plaintext[i] = output[i] ^ ciphertext[i]
                    for k in range(end-start):
                        out.append(chr(plaintext[k]))
                    text_input = output
                elif mode == self.modeOfOperation["CBC"]:
                    output = self.aes.decrypt(ciphertext, key, size)
                    for i in range(16):
                        if firstRound:
                            plaintext[i] = initialVector[i] ^ output[i]
                        else:
                            plaintext[i] = text_input[i] ^ output[i]
                    firstRound = False
                    if originalsize is not None and originalsize < end:
                        for k in range(originalsize-start):
                            out.append(chr(plaintext[k]))
                    else:
                        for k in range(end-start):
                            out.append(chr(plaintext[k]))
                    text_input = ciphertext
        return "".join(out)

#s padded to a multiple of 16-bytes by PKCS7 padding is returned in this function.
def append_padding(s):
    num_of_pads = 16 - (len(s)%16)
    return s + num_of_pads*chr(num_of_pads)


#Encryption data with key.Returned cipher is a string of bytes prepended with the initialization vector.
def encrypt_Data(key, data, mode):
    key = map(ord, key)
    if (mode == AES_Mode_Operation.modeOfOperation["CBC"]) or (mode == AES_Mode_Operation.modeOfOperation["OFB"]) :
        data = append_padding(data)
    keysize = len(key)
    assert keysize in AES.size_of_key.values(), 'invalid key size: %s' % keysize

    initial_vector = [ord(i) for i in os.urandom(16)]   # create a new initial vector using random data.
    operation = AES_Mode_Operation()
    (mode, length, ciph) = operation.encrypt(data, mode, key, keysize, initial_vector)
 
    # prepend the initial vector.
    return ''.join(map(chr, initial_vector)) + ''.join(map(chr, ciph))

# s stripped of PKCS7 padding is returned in this function.
def strip_padding(s):
    if len(s)%16 or not s:
        raise ValueError("String of length %d can't be PCKS7-padded!" % len(s))
    numpads = ord(s[-1])
    if numpads > 16:
        raise ValueError("String ending with %r can't be PCKS7-padded!" % s[-1])
    return s[:-numpads]

#Decryption data using key.
def decrypt_Data(key, data, mode):
    key = map(ord, key)
    keysize = len(key)
    assert keysize in AES.size_of_key.values(), 'Invalid key size: %s' % keysize
    iv = map(ord, data[:16])   # initial vector is first 16 bytes.
    data = map(ord, data[16:])
    operation = AES_Mode_Operation()
    decr = operation.decrypt(data, None, mode, key, keysize, iv)
    if (mode == AES_Mode_Operation.modeOfOperation["CBC"]) or (mode == AES_Mode_Operation.modeOfOperation["OFB"]):
        decr = strip_padding(decr)
    return decr

#Generate random key from data of length key size.
def generate_Random_Key(keysize):
    if keysize not in (16, 24, 32):
        emsg = 'Invalid keysize, %s. Should be one of (16, 24, 32).'
        raise ValueError, emsg % keysize
    return os.urandom(keysize)
#Calling required functions for encryption in this function.
def encryptOperation(cleartext,modeName,key):
    mode = AES_Mode_Operation.modeOfOperation[modeName]
    cipher = encrypt_Data(key, cleartext, mode)
    return [ord(x) for x in cipher]
#Calling required functions for encryption in this function.  
def decryptOperation(key,cipher,modeName):
    mode = AES_Mode_Operation.modeOfOperation[modeName]
    decr = decrypt_Data(key, cipher, mode)
    return decr
#Testing function.    
def test_function(cleartext,mode,key,keysize):
    print '\n~~~~~~~~~~~~~~~~~~~~~~~~~'
    print 'Sifrelenecek Metin: ',cleartext
    print 'Mod: ', mode
    print 'Anahtar Boyutu:',keysize , "bayt"
    print 'Rastgele Anahtar:',[ord(x) for x in key]
    cipher = encryptOperation(clearText,mode,cypherkey)
    print 'Sifrelenmis Metin: ', cipher
    cipherMessage= ""
    for i in range(0,len(cipher)):
        cipherMessage+= chr(cipher[i])
    decr = decryptOperation(cypherkey,cipherMessage,mode)
    print 'Sifresi Cozulmus(desifrelenmis) Metin: ', decr
    print '~~~~~~~~~~~~~~~~~~~~~~~~~'
  
#main method.  
if __name__ == "__main__":
    cypherkey=generate_Random_Key(16) 
    clearText = "Bu AES ve CBC modu ile sifrelenecek metindir."
    test_function(clearText,"CBC",cypherkey,16)
    clearText = "Bu AES ve OFB modu ile sifrelenecek metindir."
    test_function(clearText,"OFB",cypherkey,16)

    cypherkey=generate_Random_Key(24) 
    clearText = "Bu AES ve CBC modu ile sifrelenecek metindir."
    test_function(clearText,"CBC",cypherkey,24)
    clearText = "Bu AES ve OFB modu ile sifrelenecek metindir."
    test_function(clearText,"OFB",cypherkey,24)

    cypherkey=generate_Random_Key(32) 
    clearText = "Bu AES ve CBC modu ile sifrelenecek metindir."
    test_function(clearText,"CBC",cypherkey,32)
    clearText = "Bu AES ve OFB modu ile sifrelenecek metindir."
    test_function(clearText,"OFB",cypherkey,32)
  
