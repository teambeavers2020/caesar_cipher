# 6.001
# Pset-4 on Ceasar Cipher

from ast import Sub
from json import load
import string

VOWELS_LOWER = 'aeiou'
VOWELS_UPPER = 'AEIOU'
CONSONANTS_LOWER = 'bcdfghjklmnpqrstvwxyz'
CONSONANTS_UPPER = 'BCDFGHJKLMNPQRSTVWXYZ'

WORDLIST_FILENAME = 'words.txt'

def load_words(file_name):
    """ returns a list of words from the given file """
    print("Loading word list from file...")
    wordlist = set()
    with open(file_name,"r") as f:
        for line in f:
            wordlist.update( {l.lower() for l in line.strip().split()} )
    print(f" {len(wordlist)} loaded")
    return wordlist

def is_word(word_list, word):
    """
    Determines if word is a valid word, ignoring
    capitalization and punctuation
    """
    word = word.lower().strip(" !@#$%^&*()-_+={}[]|\:;'<>?,./\"")
    return word in word_list # booleans


def get_story_string():
    """
    Returns: a story in encrypted text.
    """
    with open("story.txt", "r") as sf:
        story = sf.read().strip()
    return story

### END HELPER CODE ###


def get_permutations(sequence):
    '''
    Enumerate all permutations of a given string
    sequence (string): an arbitrary string to permute. Assume that it is a
    non-empty string.  
    Returns: a list of all permutations of sequence (no duplicates)
    '''
    # BC: input==output
    if len(sequence) == 1:
        return sequence
    # RC: reduce & rearrange
    out = []
    for rec_elt in (get_permutations(sequence[1:])): # reduce sequence
        for ix in range(len(rec_elt) + 1): # rearrange
            out.append( rec_elt[:ix] + sequence[0] + rec_elt[ix:])
    return out


class Message (object):
    def __init__ (self, text):
        '''
        Initializes a Message object            
        text (string): the message's text
        a Message object has two attributes:
            self._text (string, determined by input text)
            self.valid_words (a set)
        '''
        self._text = text
        self.valid_words = load_words(WORDLIST_FILENAME)  # a set

    def get_message_text (self):
        return self._text
    def get_valid_words(self):
        return self.valid_words.copy() # cloning of a set

    def build_shift_dict(self, shift):
        '''
        Creates a dictionary that can be used to apply a cipher to a letter.
        The dictionary maps every uppercase and lowercase letter to a
        character shifted >Down< the alphabet by the input shift. 
        shift (integer): the amount by which to shift every letter of the 
        alphabet. 0 <= shift < 26

        Returns: a dictionary mapping a letter (string) to 
                 another letter (string). 
        '''
        lower_alpha = string.ascii_lowercase
        upper_alpha = string.ascii_uppercase

        shift_dict = {}
        for ix in range(26):
            if ix+shift >= 26: # since index: 0-25
                new_pos = (ix+shift)-26
            else:
                new_pos = ix+shift           
            shift_dict[lower_alpha[ix]] = lower_alpha[new_pos] # letter i --> letter i+k
            shift_dict[upper_alpha[ix]] = upper_alpha[new_pos] # letter i --> letter i+k
        return shift_dict


    def apply_shift(self, shift):
        '''
        Applies the Caesar Cipher to self.message_text with the input shift.
        Creates a new string that is self.message_text shifted DOWN the
        alphabet by some number of characters determined by the input shift        
        
        shift (integer): the shift with which to encrypt the message.
        0 <= shift < 26

        Returns: the message text (string) in which every character is shifted
             down the alphabet by the input shift
        '''
        # # set the shift value of the cur instance
        # self.set_shift(shift)
        # build the Dict
        shift_dict = self.build_shift_dict(shift)
        # init. a new str
        coded_text = ""
        # # shift each letter in the text
        for letter in self._text:
            if letter in shift_dict.keys():
                coded_text += shift_dict[letter]
            else:
                coded_text += letter
        # return the new str
        return coded_text


class PlaintextMessage(Message): # Message is the Parent Class
    def __init__(self, text, shift):
        '''
        Initializes a PlaintextMessage object        
        text (string): the message's text
        shift (integer): the shift associated with this message
        A PlaintextMessage object inherits from Message and has five attributes:
            self._text (string, determined by input text)
            self.valid_words (list, determined using helper function load_words)
            self._shift (integer, determined by input shift)
        '''
        # call Parent class >constructor< to inherit all Parent's attributes
        Message.__init__(self, text)
        # add new attributes for Child class
        self._shift = shift # default to be Zero; not a required input to create an instance/obj
        
    def get_shift(self):
        '''
        Used to safely access self.shift outside of the class
        '''
        return self._shift

    def get_encryption_dict(self):
        '''
        Used to safely access a copy self.encryption_dict outside of the class
        '''
        return self.build_shift_dict(self._shift).copy() # shallow copy

    def get_message_text_encrypted(self):
        '''
        Used to safely access self.message_text_encrypted outside of the class
        '''
        return self.apply_shift(self._shift)

    def change_shift(self, shift):
        '''
        Changes self.shift of the PlaintextMessage and updates other 
        attributes determined by shift.        
        shift (integer): the new shift that should be associated with this message.
        0 <= shift < 26
        Returns: nothing
        '''
        # change the value of "self._shift" to shift inside "apply_shift" method
        if 0<=shift<26: 
            self._shift = shift # return None
            # update Dict & apply on the text
            self.apply_shift(self._shift)
        else:
            raise ValueError("shift must be between 0 and 25 inclusive")


class CipherTextMessage(Message):
    def __init__(self, text):
        '''
        Initializes a CiphertextMessage object               
        text (string): the message's text
        a CiphertextMessage object has two attributes:
            self._text (string, determined by input text)
            self.valid_words (list, determined using helper function load_words)
        '''
        Message.__init__(self,text)

    def decrypt_message(self):
        '''
        Try every possible shift value and find the "best" shift to decrypt the message. 
        We will define "best" as the shift that
        creates the maximum number of real words when we use apply_shift(shift)
        on the message text. If s is the original shift value used to encrypt
        the message, then we would expect 26 - s to be the best shift value 
        for decrypting it.

        Note: if multiple shifts are equally good such that they all create 
        the maximum number of valid words, you may choose any of those shifts 
        (and their corresponding decrypted messages) to return

        Returns: a tuple of the best shift value used to decrypt the message
        and the decrypted message text using that shift value
        '''
        max_count=0 # max valid words in the text using shift k
        # try all possible shift
        for shift in range(26):
            count = 0
            msg = self.apply_shift(shift)
            # check # of valid words in the new_msg
            for word in msg.strip().split(" "):               
                if is_word(self.valid_words, word):
                    count+=1
            # for each "shift" trial
            if max_count <= count:
                best_shift = shift
                max_count= count
                best_msg = msg
        return (26-best_shift, best_msg)
            
                
######################################## Different from Pset-4 by using Inheritance ######################################################
class SubMessage(Message): # inherit
    def __init__(self, text):
        '''
        Initializes a SubMessage object        
        text (string): the message's text
        A SubMessage object has two attributes:
            self._text (string, determined by input text)
            self.valid_words (list, determined using helper function load_words)
            self.get_message_text & self.get_valid_words
        '''
        # inheritance 
        Message.__init__(self,text)
        
                
    def build_transpose_dict(self, vowels_permutation):
        '''
        vowels_permutation (string): a string containing a permutation of vowels (a, e, i, o, u)
        
        Creates a dictionary that can be used to apply a cipher to a letter.
        The dictionary maps every uppercase and lowercase letter to an
        uppercase and lowercase letter, respectively. Vowels are shuffled 
        according to vowels_permutation. The first letter in vowels_permutation 
        corresponds to a, the second to e, and so on in the order a, e, i, o, u.
        The consonants remain the same. The dictionary should have 52 
        keys of all the uppercase letters and all the lowercase letters.

        Example: When input "eaiuo":
        Mapping is a->e, e->a, i->i, o->u, u->o
        and "Hello World!" maps to "Hallu Wurld!"

        Returns: a dictionary mapping a letter (string) to 
                 another letter (string). 
        '''
        transpose_dict = {} # only for vowels
        for k, v in zip(VOWELS_LOWER, vowels_permutation.lower()):
            transpose_dict[k] = v
        for K, V in zip(VOWELS_UPPER, vowels_permutation.upper()):
            transpose_dict[K] = V

        # for consonants, key=value
        all_consonants = CONSONANTS_LOWER +CONSONANTS_UPPER
        for kc, vc in zip(all_consonants, all_consonants):
            transpose_dict[kc] = vc

        return transpose_dict


    def apply_transpose(self, transpose_dict):
        '''
        transpose_dict (dict): a transpose dictionary
        
        Returns: an encrypted version of the message text, based 
        on the dictionary
        '''
        new_msg = ""
        for letter in self._text:
            if letter.isalpha():
                new_msg += transpose_dict[letter]
            else:
                new_msg += letter
        return new_msg
        
class EncryptedSubMessage(SubMessage):
    def __init__(self, text):
        '''
        Initializes an EncryptedSubMessage object

        text (string): the encrypted message text

        An EncryptedSubMessage object inherits from SubMessage and has two attributes:
            self.message_text (string, determined by input text)
            self.valid_words (list, determined using helper function load_words)
        '''
        SubMessage.__init__(self, text)

    def decrypt_message(self):
        '''
        Attempt to decrypt the encrypted message 
        
        Idea is to go through each permutation of the vowels and test it
        on the encrypted message. For each permutation, check how many
        words in the decrypted text are valid English words, and return
        the decrypted message with the most English words.
        
        If no good permutations are found (i.e. no permutations result in 
        at least 1 valid word), return the original string. If there are
        multiple permutations that yield the maximum number of words, return any
        one of them.

        Returns: the best decrypted message    
        '''
        vowels_permutation = get_permutations(VOWELS_LOWER) # a list of all permutations (no duplicates)
        valid_words = self.get_valid_words() # a set of valid words
        # initialize
        best_perm = ""
        max_words_count = 0
        best_decrypted_text = ""
        
        # build a Dict & apply on text for each permutations
        for perm in vowels_permutation:
            transpose_dict = self.build_transpose_dict(perm)
            decrypted_text = self.apply_transpose(transpose_dict)
            count= 0 # reset for each decrypted text
            for word in decrypted_text.strip().split():
                # check num of valid words 
                if is_word(valid_words, word):
                    count +=1
                # compare & reassign
            if count >= max_words_count:
                max_words_count = count
                best_perm = perm
                best_decrypted_text = decrypted_text
            
        # return the best if exist
        if max_words_count > 0:
            return best_decrypted_text
        # else - raise Error
        else:
            raise Exception("No Valid Words Was Found after using all vowels permutation.")
        


if __name__ == '__main__':

    assert set(get_permutations("abc")) == {'abc', 'acb', 'bac', 'bca', 'cab', 'cba'}
    assert len(get_permutations("abc")) == 6
    assert len(get_permutations("abcdefgh")) == 40320

    # object1 = Message("azx")
    # shift_dict_test = object1.build_shift_dict(3)
    # print(shift_dict_test)
    # print("coded text: ", object1.apply_shift(5))
    # # print("coded text: ", object1.apply_shift(26)) # a ValueError
    # child_obj = PlaintextMessage("abc", 2)
    # print("get shift:",child_obj.get_shift())
    # child_obj.change_shift(7)
    # print("get shift after chaging to 7 :", child_obj.get_shift())
    # print(child_obj.get_message_text_encrypted())

    ############### Testing PlainTextMessage & CipherTextMessage ################

    # decoded_story  = CipherTextMessage(get_story_string()) # create an instance
    # print("\ndecoded story: \n", decoded_story.decrypt_message())

    # plain_text = decoded_story.decrypt_message()[1]
    # encoded_story = PlaintextMessage(plain_text, 14) # create an instance
    # print("\nencrypted story: \n", encoded_story.get_message_text_encrypted())
    

    # ###################### Testing SubMessage ##################################
    # print("\n\n")
    # msg = SubMessage("Hello World!")
    # permutation = "eaiuo"
    # enc_dict = msg.build_transpose_dict(permutation)
    # # print(enc_dict)
    # print("Original message:", msg.get_message_text(), "& Permutation:", permutation)
    # print("Expected encryption:", "Hallu Wurld!")
    # print("Actual encryption:", msg.apply_transpose(enc_dict))
    
    # enc_message = EncryptedSubMessage(msg.apply_transpose(enc_dict))
    # print("Decrypted message:", enc_message.decrypt_message())
     
    # # WRITE MORE TEST CASES HERE
    # msg_1 = SubMessage("Cat and Dog are awesome! What more vowels should I test?")
    # msg_1_dict = msg_1.build_transpose_dict("euoai")
    # encrypted_msg_1 = msg_1.apply_transpose(msg_1_dict)
    # print("Encrypted Message: ", encrypted_msg_1)
    # msg_2 = EncryptedSubMessage(encrypted_msg_1)
    # print("Decrypted message:", msg_2.decrypt_message())



    plain_text = "I Love Baby Gyi!! <3<3<3"
    encoded_story = PlaintextMessage(plain_text, 5) # create an instance
    print("\nencrypted story: \n", encoded_story.get_message_text_encrypted())

    decoded_story  = CipherTextMessage("N Qtaj Gfgd Ldn!! <3<3<3") # create an instance
    print("\ndecoded story: \n", decoded_story.decrypt_message())
