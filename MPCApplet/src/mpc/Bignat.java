package mpc;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

public class Bignat {
        public static byte[] fastResizeArray = null;
        
	/**
	* True for the short/short configuration, false otherwise.
	*/
	public static final boolean use_short_digits = true;

	/**
	* Factor for converting digit size into short length. 1 for the short/short
	* converting, 4 for the int/long configuration.
	* 
	*/
	public static final short size_multiplier = 1;

	/**
	* Bitmask for extracting a digit out of a longer int/short value. short
	* 0xff for the short/short configuration, long 0xffffffffL the int/long
	* configuration.
	*/
	public static final short digit_mask = 0xff;

	/**
	* Bitmask for the highest bit in a digit. short 0x80 for the short/short
	* configuration, long 0x80000000 for the int/long configuration.
	* 
	*/
	public static final short digit_first_bit_mask = 0x80;

	/**
	* Bitmask for the second highest bit in a digit. short 0x40 for the
	* short/short configuration, long 0x40000000 for the int/long
	* configuration.
	* 
	*/
	public static final short digit_second_bit_mask = 0x40;

	/**
	* Bitmask for the two highest bits in a digit. short 0xC0 for the
	* short/short configuration, long 0xC0000000 for the int/long
	* configuration.
	* 
	*/
	public static final short digit_first_two_bit_mask = 0xC0;

	/**
	* Size in bits of one digit. 8 for the short/short configuration, 32 for
	* the int/long configuration.
	*/
	public static final short digit_len = 8;

	/**
	* Size in bits of a double digit. 16 for the short/short configuration, 64
	* for the int/long configuration.
	*/
	private static final short double_digit_len = 16;

	/**
	* Bitmask for erasing the sign bit in a double digit. short 0x7fff for the
	* short/short configuration, long 0x7fffffffffffffffL for the int/long
	* configuration.
	*/
	private static final short positive_double_digit_mask = 0x7fff;

	/**
	* Bitmask for the highest bit in a double digit.
	*/
	public static final short highest_digit_bit = (short) (1L << (digit_len - 1));

	/**
	* The base as a double digit. The base is first value that does not fit
	* into a single digit. 2^8 for the short/short configuration and 2^32 for
	* the int/long configuration.
	*/
	public static final short bignat_base = (short) (1L << digit_len);

	/**
	* Bitmask with just the highest bit in a double digit.
	*/
	public static final short highest_double_digit_bit = (short) (1L << (double_digit_len - 1));

	/**
	* Digit array. Elements have type byte.
	*/
        private byte[] value;
        private short[] valueShort; // used to speedup some operations

        static KeyPair      mult_keypair = null;
        static RSAPublicKey mult_pubkey_pow2 = null;
        static Cipher       mult_cipher = null;
        static KeyPair      mod_keypair = null;
        static RSAPublicKey mod_pubkey_pow1 = null;
        static Cipher       mod_cipher = null;
        static byte[] CONST_ONE = {0x01};
        static byte[] CONST_TWO = {0x02};
        //static final short MULT_RSA_LENGTH = KeyBuilder.LENGTH_RSA_736; // RSA length bigger than 32x32B
        static final short MULT_RSA_LENGTH = KeyBuilder.LENGTH_RSA_1024; // RSA length bigger than 32x32B
        static final short MOD_RSA_LENGTH = KeyBuilder.LENGTH_RSA_512; // for modulo
        //static final short MULT_RSA_LENGTH = KeyBuilder.LENGTH_RSA_1280; // RSA length bigger than 64x64B
        static byte[] mult_resultArray = null;
        static byte[] mult_resultArray2 = null;
        
        static byte[] shifted_r = {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xbc, (byte) 0xe6, (byte) 0xfa, (byte) 0xad, (byte) 0xa7, (byte) 0x17, (byte) 0x9e, (byte) 0x84, (byte) 0xf3, (byte) 0xb9, (byte) 0xca, (byte) 0xc2, (byte) 0xfc, (byte) 0x63, (byte) 0x25, (byte) 0x51, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        
        static void allocate() {
            fastResizeArray = JCSystem.makeTransientByteArray(Consts.MAX_BIGNAT_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
            mult_resultArray = JCSystem.makeTransientByteArray((short) (MULT_RSA_LENGTH / 8), JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
            mult_resultArray2 = JCSystem.makeTransientByteArray((short) (MULT_RSA_LENGTH / 8), JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
            
            try {
                // Speedup for fast multiplication
                mult_keypair = new KeyPair(KeyPair.ALG_RSA_CRT, MULT_RSA_LENGTH);
                mult_keypair.genKeyPair();
                mult_pubkey_pow2 = (RSAPublicKey) mult_keypair.getPublic();
                mult_pubkey_pow2.setExponent(CONST_TWO, (short) 0, (short) CONST_TWO.length);
                mult_cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
                mult_cipher.init(mult_pubkey_pow2, Cipher.MODE_ENCRYPT);
                Util.arrayFillNonAtomic(mult_resultArray, (short) 0, (short) mult_resultArray.length, (byte) 6);
                mult_cipher.doFinal(mult_resultArray, (short) 0, (short) mult_resultArray.length, mult_resultArray, (short) 0);
/*                
                // Speedup for fast modulo
                mod_keypair = new KeyPair(KeyPair.ALG_RSA_CRT, MOD_RSA_LENGTH);
                mod_keypair.genKeyPair();
                mod_pubkey_pow1 = (RSAPublicKey) mod_keypair.getPublic();
                mod_pubkey_pow1.setExponent(CONST_ONE, (short) 0, (short) CONST_ONE.length);
                mod_pubkey_pow1.setModulus(shifted_r, (short) 0, (short) shifted_r.length);

                mod_cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
                mod_cipher.init(mod_pubkey_pow1, Cipher.MODE_ENCRYPT);

                Util.arrayFillNonAtomic(mult_resultArray, (short) 0, (short) mult_resultArray.length, (byte) 6);
                mod_cipher.doFinal(mult_resultArray, (short) 0, (short) (MOD_RSA_LENGTH / 8), mult_resultArray, (short) 0);
*/                
            }
            catch (Exception e) {
                ISOException.throwIt(Consts.SW_CANTALLOCATE_BIGNAT);
            }
        }
	/**
	* Return the digit array. The return value has type {@code byte[]}. The
	* {@link #value} field is simply returned, without making a copy. Modifying
	* the returned array will modify this Bignat.
	* 
	* @return a reference to {@link #value} of type {@code byte[]}
	*/
	public byte[] get_digit_array() {
		return value;
	}

	/**
	* Return this Bignat as short array. For the short/short configuration
	* simply the digit array is returned. For other configurations a new short
	* array is allocated and returned. Modifying the returned short array
	* therefore might or might not change this bignat.
	* 
	* @return this bignat as short array
	*/
	public byte[] as_byte_array() { // BUGBUG: as_byte_array() now returns whole array and potentially ignores size attribute
		return value;
	}

        private short size;
        private short max_size = -1; // maximum allocated size

	/**
	* Size in shorts necessary to send or receive this object via the OV-chip
	* protocol layer, see {@link ds.ov2.util.APDU_Serializable#size
	* APDU_Serializable.size()}.
	* <P>
	* 
	* For configurations different from short/short the returned value
	* obviously differs from the length of the {@link #value} array and also
	* from the {@link #size} attribute.
	* <P>
	* The return value is adjusted by {@link #resize}.
	* 
	* @return size in shorts
	*/
	public short size() {
		return (short) (size * size_multiplier);
	}

        void resizeToMaxSize() {
            resize(max_size);
            zero();
        }
	/**
	* Return the size in digits. Provides access to the internal {@link #size}
	* field.
	* <P>
	* The return value is adjusted by {@link #resize}.
	* 
	* @return size in digits.
	*/
	public short length() {
		return size;
	}

	/**
	* Construct a Bignat of size {@code size} in shorts. Allocated in RAM if
	* {@code ram} is true, in EEPROM otherwise. In the int/long configuration
	* asserts that size is divisable by 4. In this configuration the number of
	* digits is obviously {@code size / 4}. Relies on
	* {@link ds.ov2.util.Misc#allocate_transient_short_array
	* Misc.allocate_transient_short_array} for allocation in transient (RAM)
	* memory.
	* 
	* @param size
	*            the size of the new Bignat in shorts, must be divisible by 4
	*            for the int/long configuration
	* @param ram
	*            allocate in transient RAM if true
	*/
        public Bignat(short size, boolean bShortSpeedup) {
		this.size = size;
                this.max_size = size;
                value = JCSystem.makeTransientByteArray(size, JCSystem.CLEAR_ON_RESET);
                
                if (bShortSpeedup) {
                    valueShort = JCSystem.makeTransientShortArray(size, JCSystem.CLEAR_ON_RESET);
                }
	}
	
    /**
     * Resize this Bignat.
     *
     * MAKE SURE THAT IT'S SMALLER OR EQUAL TO THE CURRENT SIZE,
     * OTHERWISE YOU ON YOUR OWN, AND HELL WILL BREAK LOOSE.
     * ---------NOPE----------
     * Only available when VARIABLE_SIZE_BIGNATS is defined. Works only 
     * for the byte/short configuration, otherwise an assertion is thrown.
     * Asserts that the new size {@code s} is smaller or equal to the 
     * size specified in the constructor.
     *---------NOPE----------
     * @param new_size new size in bytes, must be
     * divisible by 4 for the int/long configuration
     */
    void resize(short new_size) {
        //assert((new_size % size_multiplier == 0) && ((short)(new_size / size_multiplier) <= value.length));
        //this.size = (short)(new_size / size_multiplier);
        if (new_size > this.max_size) {
            ISOException.throwIt((short) -1); // cannot increase more than was originally allocated for
        }
	this.size = new_size;
    }

    
    /**
     * Resize this Bignat.
     * 
     * Same behaviour as copy.
     *
     * @param new_size new size in bytes, must be
     * divisible by 4 for the int/long configuration
     */
    void deep_resize(short new_size) {
        if (new_size > this.max_size) {
            ISOException.throwIt((short) -1); // cannot increase more than was originally allocated for
        }
        short this_start, other_start, len;
        if (this.size >= new_size) {
            this_start = (short) (this.size - new_size);
            other_start = 0;
            len = new_size;

            // Shrinking 
            Util.arrayCopyNonAtomic(value, this_start, fastResizeArray, (short) 0, len);
            Util.arrayCopyNonAtomic(fastResizeArray, (short) 0, value, (short) 0, len); // Move bytes in item array towards beggining
/*
            for (short i = 0; i < len; i++) {
                value[i] = value[(short) (i + this_start)]; 
            }
*/            
            // Erase rest of allocated array with zeroes (just as sanitization)
            Util.arrayFillNonAtomic(value, new_size, (short) (this.max_size - new_size), (byte) 0); 
        } else {
            this_start = 0;
            other_start = (short) (new_size - this.size);
            len = this.size;
            // Enlarging => Insert zeroes at begging, move bytes in item array towards end
            //short new_size_offset = (short) (new_size - 1);

            Util.arrayCopyNonAtomic(value, this_start, fastResizeArray, (short) 0, len);
            // Move bytes in item array towards end
            Util.arrayCopyNonAtomic(fastResizeArray, (short) 0, value, other_start, len); 
            // Fill begin of array with zeroes (just as sanitization)
            Util.arrayFillNonAtomic(value, (short) 0, other_start, (byte) 0);
            
/*            
            for (short i = (short) (len - 1); i >= 0; i--) {
                value[new_size_offset] = value[i];
                new_size_offset--;
            }
            while (new_size_offset >= (byte) 0) {
                value[new_size_offset] = (byte) 0;
                new_size_offset--;
            }
*/            
        }

        //byte[] tmp_value = new byte[new_size];
        //Util.arrayFillNonAtomic(tmp_value, (short) 0, (short) tmp_value.length, (byte) 0); //fill with zeros
        //Util.arrayCopy(value, this_start, tmp_value, other_start, len); //copy the value
        //Util.arrayCopyNonAtomic(value, this_start, value, other_start, len); //copy the value

        resize(new_size);
        //this.size = (short)(new_size);
        //value = tmp_value;

        //value = new byte[new_size];
        //Util.arrayCopy(tmp_value, (short) 0, value, (short)0, this.size); //copy tmp_value to value
        //JCSystem.requestObjectDeletion(); //to remove tmp_value
    }
    
    
    void shrink() {
        short i = 0;
        for (i = 0; i < (short) this.value.length; i++) {
            if (this.value[i] != 0) {
                break;
            }
        }

		short new_size = (short)(this.size-i);
		//if (new_size==1)
		//	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		//while (new_size%(short)4 != 0) //find closest multiple of 4
		//	new_size++;
		
		if (new_size<(short)4)
			new_size=(short)4;
			
		this.deep_resize(new_size);
		//JCSystem.requestObjectDeletion();
    }
    
    
	/**
	* Stores zero in this object.
	*/
    public void zero() {
        Util.arrayFillNonAtomic(value, (short) 0, this.size, (byte) 0);
    }

    void prepareShortValueHelper() {
        if (valueShort == null) {
            ISOException.throwIt((short) -1);
        }
        else {
            for (short i = 0; i < (short) value.length; i++) {
                valueShort[i] = (short) (value[i] & digit_mask);
            }
        }
    }
    
    void restoreFromShortValueHelper() {
        if (valueShort == null) {
            ISOException.throwIt((short) -1);
        } else {
            for (short i = 0; i < (short) value.length; i++) {
                value[i] = (byte) (valueShort[i] & digit_mask);
            }
        }
    }    
        
	
	/**
	* Stores one in this object.
	*/
	public void one() {
		this.zero();
		value[(short) (size - 1)] = 1;
	}

	
	/**
	* 
	* Stores two in this object.
	*/
	public void two() {
		this.zero();
		value[(short) (size - 1)] = 2;
	}

	
	public void four() {
		this.zero();
		value[(short) (size - 1)] = 4;
	}

	public void five() {
		this.zero();
		value[(short) (size - 1)] = 5;
	}
	
	
	public void eight() {
		this.zero();
		value[(short) (size - 1)] = 8;
	}
	
    public void twentyfive() {
        this.zero();
        value[(short)(size-1)] = 0x19;
    }

    public void athousand() {
        this.zero();
        value[(short)(size-2)] = (byte)0x03;
        value[(short)(size-1)] = (byte)0xE8;
    }
    
    
	/**
	* 
	* Sets byte of the object.
	*/
	public void setByte(short ind, byte val) {
		value[ind] = val;
	}
	
	public byte getByte(short ind) {
		return value[ind];
	}
    

	/**
	* 
	* Sets last byte of the object.
	*/
	public void setLastByte(byte val) {
		this.zero();
		value[(short) (size - 1)] = val;
	}
	
	public byte getLastByte() {
		return value[(short) (size - 1)];
	}

	/**
	* Copies {@code other} into this. No size requirements. If {@code other}
	* has more digits then the superfluous leading digits of {@code other} are
	* asserted to be zero. If this bignat has more digits than its leading
	* digits are correctly initilized to zero.
	* 
	* @param other
	*            Bignat to copy into this object.
	*/
	public void copy(Bignat other) {
		short this_start, other_start, len;
		if (this.size >= other.size) {
			this_start = (short) (this.size - other.size);
			other_start = 0;
			len = other.size;
		} else {
			this_start = 0;
			other_start = (short) (other.size - this.size);
			len = this.size;
		}

		for (short i = 0; i < this_start; i++)
			this.value[i] = 0;

		Util.arrayCopyNonAtomic(other.value, other_start, this.value, this_start, len);
	}

	/**
	* Equality check. Requires that this object and other have the same size.
	* Returns true if all digits are equal.
	* 
	* 
	* @param other
	*            Bignat to compare
	* @return true if this and other have the same value, false otherwise.
	*/
/*
	public boolean same_value(Bignat other) {
		for (short i = 0; i < size; i++)
			if (this.value[i] != other.value[i])
				return false;
		return true;
	}
*/
	
	
	public boolean same_value(Bignat other) {
		for (short i = (short)(size-1); i <= 0; i--)
			if (this.value[i] != other.value[i])
				return false;
		return true;
	}
	
	
	/**
	* Addition of big integer x and y specified by offset and length the result
	* is saved in x
	* 
	* @param x
	* @param xOffset
	* @param xLength
	* @param y
	* @param yOffset
	* @param yLength
	* @return
	*/
	public static boolean add(byte[] x, short xOffset, short xLength, byte[] y,
			short yOffset, short yLength) {
		short digit_mask = 0xff;
		short digit_len = 0x08;
		short result = 0;
		short i = (short) (xLength + xOffset - 1);
		short j = (short) (yLength + yOffset - 1);

		for (; i >= xOffset; i--, j--) {
			result = (short) (result + (short) (x[i] & digit_mask) + (short) (y[j] & digit_mask));

			x[i] = (byte) (result & digit_mask);
			result = (short) ((result >> digit_len) & digit_mask);
		}
		while (result > 0 && i >= xOffset) {
			result = (short) (result + (short) (x[i] & digit_mask));
			x[i] = (byte) (result & digit_mask);
			result = (short) ((result >> digit_len) & digit_mask);
			i--;
		}

		return result != 0;
	}

	/**
	* subtracts big integer y from x specified by offset and length the result
	* is saved in x
	* 
	* @param x
	* @param xOffset
	* @param xLength
	* @param y
	* @param yOffset
	* @param yLength
	* @return
	*/
	public static boolean subtract(byte[] x, short xOffset, short xLength, byte[] y,
			short yOffset, short yLength) {
		short digit_mask = 0xff;
		short i = (short) (xLength + xOffset - 1);
		short j = (short) (yLength + yOffset - 1);
		short carry = 0;
		short subtraction_result = 0;

		for (; i >= xOffset && j >= yOffset; i--, j--) {
			subtraction_result = (short) ((x[i] & digit_mask)
					- (y[j] & digit_mask) - carry);
			x[i] = (byte) (subtraction_result & digit_mask);
			carry = (short) (subtraction_result < 0 ? 1 : 0);
		}
		for (; i >= xOffset && carry > 0; i--) {
			if (x[i] != 0)
				carry = 0;
			x[i] -= 1;
		}

		return carry > 0;
	}
	/**
	* 
	* Modular subtraction. Computes {@code (this - other) modulo mod} and
	* stores the result in this Bignat. This bignat and {@code other} must be
	* less then {@code mod}, otherwise strange things can happen.
	* 
	* @param other
	*            value to subtract
	* @param mod
	*            modulus
	*/

	/**
	* Scaled subtraction. Subtracts {@code mult * 2^(}{@link #digit_len}
	* {@code  * shift) * other} from this.
	* <P>
	* That is, shifts {@code mult * other} precisely {@code shift} digits to
	* the left and subtracts that value from this. {@code mult} must be less
	* than {@link #bignat_base}, that is, it must fit into one digit. It is
	* only declared as short here to avoid negative values.
	* <P>
	* {@code mult} has type short.
	* <P>
	* No size constraint. However, an assertion is thrown, if the result would
	* be negative. {@code other} can have more digits than this object, but
	* then sufficiently many leading digits must be zero to avoid the
	* underflow.
	* <P>
	* Used in division.
	* 
	* @param other
	*            Bignat to subtract from this object
	* @param shift
	*            number of digits to shift {@code other} to the left
	* @param mult
	*            of type short, multiple of {@code other} to subtract from this
	*            object. Must be below {@link #bignat_base}.
	*/
	public void times_minus(Bignat other, short shift, short mult) {
		short akku = 0;
		short subtraction_result;
		short i = (short) (this.size - 1 - shift);
		short j = (short) (other.size - 1);
		for (; i >= 0 && j >= 0; i--, j--) {
			akku = (short) (akku + (short) (mult * (other.value[j] & digit_mask)));
			subtraction_result = (short) ((value[i] & digit_mask) - (akku & digit_mask));

			// if(debug) {
			// System.out.format("TM %d: this %02X other %02X mult %04X " +
			// "akku %04X sub res %04X\n",
			// i,
			// value[i] & 0xff,
			// other.value[i] & 0xff,
			// mult,
			// akku & 0xffff,
			// subtraction_result & 0xffff);
			// }

			value[i] = (byte) (subtraction_result & digit_mask);
			akku = (short) ((akku >> digit_len) & digit_mask);
			if (subtraction_result < 0)
				akku++;
		}

		// deal with carry as long as there are digits left in this
		while (i >= 0 && akku != 0) {
			subtraction_result = (short) ((value[i] & digit_mask) - (akku & digit_mask));
			value[i] = (byte) (subtraction_result & digit_mask);
			akku = (short) ((akku >> digit_len) & digit_mask);
			if (subtraction_result < 0)
				akku++;
			i--;
		}

		return;
	}

	/**
	* Index of the most significant 1 bit.
	* <P>
	* {@code x} has type short.
	* <P>
	* Utility method, used in division.
	* 
	* @param x
	*            of type short
	* @return index of the most significant 1 bit in {@code x}, returns
	*         {@link #double_digit_len} for {@code x == 0}.
	*/
	private static short highest_bit(short x) {
		for (short i = 0; i < double_digit_len; i++) {
			if (x < 0)
				return i;
			x <<= 1;
		}
		return double_digit_len;
	}

	/**
	* Shift to the left and fill. Takes {@code high} {@code middle} {@code low}
	* as 4 digits, shifts them {@code shift} bits to the left and returns the
	* most significant {@link #double_digit_len} bits.
	* <P>
	* Utility method, used in division.
	* 
	* 
	* @param high
	*            of type short, most significant {@link #double_digit_len} bits
	* @param middle
	*            of type byte, middle {@link #digit_len} bits
	* @param low
	*            of type byte, least significant {@link #digit_len} bits
	* @param shift
	*            amount of left shift
	* @return most significant {@link #double_digit_len} as short
	*/
	private static short shift_bits(short high, byte middle, byte low,
			short shift) {

		// shift high
		high <<= shift;

		// merge middle bits
		byte mask = (byte) (digit_mask << (shift >= digit_len ? 0 : digit_len
				- shift));
		short bits = (short) ((short) (middle & mask) & digit_mask);
		if (shift > digit_len)
			bits <<= shift - digit_len;
		else
			bits >>>= digit_len - shift;
		high |= bits;

		if (shift <= digit_len) {

			return high;
		}

		// merge low bits
		mask = (byte) (digit_mask << double_digit_len - shift);
		bits = (short) ((((short) (low & mask) & digit_mask) >> double_digit_len
				- shift));
		high |= bits;

		return high;
	}

	/**
	* Scaled comparison. Compares this number with {@code other * 2^(}
	* {@link #digit_len} {@code * shift)}. That is, shifts {@code other}
	* {@code shift} digits to the left and compares then. This bignat and
	* {@code other} will not be modified inside this method.
	* <P>
	* 
	* As optimization {@code start} can be greater than zero to skip the first
	* {@code start} digits in the comparison. These first digits must be zero
	* then, otherwise an assertion is thrown. (So the optimization takes only
	* effect when <a
	* href="../../../overview-summary.html#NO_CARD_ASSERT">NO_CARD_ASSERT</a>
	* is defined.)
	* 
	* @param other
	*            Bignat to compare to
	* @param shift
	*            left shift of other before the comparison
	* @param start
	*            digits to skip at the beginning
	* @return true if this number is strictly less than the shifted
	*         {@code other}, false otherwise.
	*/
	public boolean shift_lesser(Bignat other, short shift, short start) {
		short j;

		j = (short) (other.size + shift - this.size + start);

		short this_short, other_short;
		for (short i = start; i < this.size; i++, j++) {
			this_short = (short) (this.value[i] & digit_mask);
			if (j >= 0 && j < other.size)
				other_short = (short) (other.value[j] & digit_mask);
			else
				other_short = 0;
			if (this_short < other_short)
				return true;
			if (this_short > other_short)
				return false;
		}
		return false;
	}

	/**
	* Comparison.
	* 
	* @param other
	*            Bignat to compare with
	* @return true if this number is strictly lesser than {@code other}, false
	*         otherwise.
	*/
	// Return true, if this < other, false otherwise.
	public boolean lesser(Bignat other) {
		return this.shift_lesser(other, (short) 0, (short) 0);
	}

	/**
	* Test equality with zero.
	* 
	* @return true if this bignat equals zero.
	*/
	public boolean is_zero() {
		for (short i = 0; i < size; i++) {
			if (value[i] != 0)
				return false;
		}
		return true;
	}

	/**
	* Remainder and Quotient. Divide this number by {@code divisor} and store
	* the remainder in this. If {@code quotient} is non-null store the quotient
	* there.
	* <P>
	* There are no direct size constraints, but if {@code quotient} is
	* non-null, it must be big enough for the quotient, otherwise an assertion
	* is thrown.
	* <P>
	* Uses schoolbook division inside and has O^2 complexity in the difference
	* of significant digits of the divident (in this number) and the divisor.
	* For numbers of equal size complexity is linear.
	* 
	* @param divisor
	*            must be non-zero
	* @param quotient
	*            gets the quotient if non-null
	*/
	public void remainder_divide(Bignat divisor, Bignat quotient) {
		// There are some size requirements, namely that quotient must
		// be big enough. However, this depends on the value of the
		// divisor and is therefore not stated here.

		// zero-initialize the quotient, because we are only adding to it below
		if (quotient != null)
			quotient.zero();

		// divisor_index is the first nonzero digit (short) in the divisor
		short divisor_index = 0;
		while (divisor.value[divisor_index] == 0)
			divisor_index++;

		// The size of this might be different from divisor. Therefore,
		// for the first subtraction round we have to shift the divisor
		// divisor_shift = this.size - divisor.size + divisor_index
		// digits to the left. If this amount is negative, then
		// this is already smaller then divisor and we are done.
		// Below we do divisor_shift + 1 subtraction rounds. As an
		// additional loop index we also count the rounds (from
		// zero upwards) in division_round. This gives access to the
		// first remaining divident digits.

		short divisor_shift = (short) (this.size - divisor.size + divisor_index);
		short division_round = 0;

		// We could express now a size constraint, namely that
		// divisor_shift + 1 <= quotient.size
		// However, in the proof protocol we divide x / v, where
		// x has 2*n digits when v has n digits. There the above size
		// constraint is violated, the division is however valid, because
		// it will always hold that x < v * (v - 1) and therefore the
		// quotient will always fit into n digits.

		// System.out.format("XX this size %d div ind %d div shift %d " +
		// "quo size %d\n" +
		// "%s / %s\n",
		// this.size,
		// divisor_index,
		// divisor_shift,
		// quotient != null ? quotient.size : -1,
		// this.to_hex_string(),
		// divisor.to_hex_string());

		// The first digits of the divisor are needed in every
		// subtraction round.
		short first_divisor_digit = (short) (divisor.value[divisor_index] & digit_mask);
		short divisor_bit_shift = (short) (highest_bit((short) (first_divisor_digit + 1)) - 1);
		byte second_divisor_digit = divisor_index < (short) (divisor.size - 1) ? divisor.value[(short) (divisor_index + 1)]
				: 0;
		byte third_divisor_digit = divisor_index < (short) (divisor.size - 2) ? divisor.value[(short) (divisor_index + 2)]
				: 0;

		// The following variables are used inside the loop only.
		// Declared here as optimization.
		// divident_digits and divisor_digit hold the first one or two
		// digits. Needed to compute the multiple of the divisor to
		// subtract from this.
		short divident_digits, divisor_digit;

		// To increase precisision the first digits are shifted to the
		// left or right a bit. The following variables compute the shift.
		short divident_bit_shift, bit_shift;

		// Declaration of the multiple, with which the divident is
		// multiplied in each round and the quotient_digit. Both are
		// a single digit, but declared as a double digit to avoid the
		// trouble with negative numbers. If quotient != null multiple is
		// added to the quotient. This addition is done with quotient_digit.
		short multiple, quotient_digit;
		while (divisor_shift >= 0) {

			// Keep subtracting from this until
			// divisor * 2^(8 * divisor_shift) is bigger than this.
			while (!shift_lesser(divisor, divisor_shift,
					(short) (division_round > 0 ? division_round - 1 : 0))) {
				// this is bigger or equal than the shifted divisor.
				// Need to subtract some multiple of divisor from this.
				// Make a conservative estimation of the multiple to subtract.
				// We estimate a lower bound to avoid underflow, and continue
				// to subtract until the remainder in this gets smaller than
				// the shifted divisor.
				// For the estimation get first the two relevant digits
				// from this and the first relevant digit from divisor.
				divident_digits = division_round == 0 ? 0
						: (short) ((short) (value[(short) (division_round - 1)]) << digit_len);
				divident_digits |= (short) (value[division_round] & digit_mask);

				// The multiple to subtract from this is
				// divident_digits / divisor_digit, but there are two
				// complications:
				// 1. divident_digits might be negative,
				// 2. both might be very small, in which case the estimated
				// multiple is very inaccurate.
				if (divident_digits < 0) {
					// case 1: shift both one bit to the right
					// In standard java (ie. in the test frame) the operation
					// for >>= and >>>= seems to be done in integers,
					// even if the left hand side is a short. Therefore,
					// for a short left hand side there is no difference
					// between >>= and >>>= !!!
					// Do it the complicated way then.
					divident_digits = (short) ((divident_digits >>> 1) & positive_double_digit_mask);
					divisor_digit = (short) ((first_divisor_digit >>> 1) & positive_double_digit_mask);
				} else {
					// To avoid case 2 shift both to the left
					// and add relevant bits.
					divident_bit_shift = (short) (highest_bit(divident_digits) - 1);
					// Below we add one to divisor_digit to avoid underflow.
					// Take therefore the highest bit of divisor_digit + 1
					// to avoid running into the negatives.
					bit_shift = divident_bit_shift <= divisor_bit_shift ? divident_bit_shift
							: divisor_bit_shift;

					divident_digits = shift_bits(
							divident_digits,
							division_round < (short) (this.size - 1) ? value[(short) (division_round + 1)]
									: 0,
							division_round < (short) (this.size - 2) ? value[(short) (division_round + 2)]
									: 0, bit_shift);
					divisor_digit = shift_bits(first_divisor_digit,
							second_divisor_digit, third_divisor_digit,
							bit_shift);

				}

				// add one to divisor to avoid underflow
				multiple = (short) (divident_digits / (short) (divisor_digit + 1));

				// Our strategy to avoid underflow might yield multiple == 0.
				// We know however, that divident >= divisor, therefore make
				// sure multiple is at least 1.
				if (multiple < 1)
					multiple = 1;

				times_minus(divisor, divisor_shift, multiple);

				// build quotient if desired
				if (quotient != null) {
					// Express the size constraint only here. The check is
					// essential only in the first round, because
					// divisor_shift decreases. divisor_shift must be
					// strictly lesser than quotient.size, otherwise
					// quotient is not big enough. Note that the initially
					// computed divisor_shift might be bigger, this
					// is OK, as long as we don't reach this point.

					quotient_digit = (short) ((quotient.value[(short) (quotient.size - 1 - divisor_shift)] & digit_mask) + multiple);
					quotient.value[(short) (quotient.size - 1 - divisor_shift)] = (byte) (quotient_digit);
				}
			}

			// treat loop indices
			division_round++;
			divisor_shift--;
		}
	}

	public boolean add(short other) {
		short akku = 0;
		short j = (short) (this.size - 1);
		for (short i = (short) (2 - 1); i >= 0; i--, j--) {
			akku = (short) (akku + (short) (this.value[j] & digit_mask) + (short) (Utils.shortToByteArray(other)[i] & digit_mask));

			this.value[j] = (byte) (akku & digit_mask);
			akku = (short) ((akku >> digit_len) & digit_mask);
		}
		// add carry at position j
		while (akku > 0 && j >= 0) {
			akku = (short) (akku + (short) (this.value[j] & digit_mask));
			this.value[j] = (byte) (akku & digit_mask);
			akku = (short) ((akku >> digit_len) & digit_mask);
			j--;
		}

		return akku != 0;
	}
	
	
	/**
	* Addition with carry report. Adds other to this number. If this is too
	* small for the result (i.e., an overflow occurs) the method returns true.
	* Further, the result in {@code this} will then be the correct result of an
	* addition modulo the first number that does not fit into {@code this} (
	* {@code 2^(}{@link #digit_len}{@code * }{@link #size this.size}{@code )}),
	* i.e., only one leading 1 bit is missing. If there is no overflow the
	* method will return false.
	* <P>
	* 
	* It would be more natural to report the overflow with an
	* {@link javacard.framework.UserException}, however its
	* {@link javacard.framework.UserException#throwIt throwIt} method dies with
	* a null pointer exception when it runs in a host test frame...
	* <P>
	* 
	* Asserts that the size of other is not greater than the size of this.
	* 
	* @param other
	*            Bignat to add
	*/
	public boolean add_carry(Bignat other) {
		short akku = 0;
		short j = (short) (this.size - 1);
		for (short i = (short) (other.size - 1); i >= 0; i--, j--) {
			akku = (short) (akku + (short) (this.value[j] & digit_mask) + (short) (other.value[i] & digit_mask));

			this.value[j] = (byte) (akku & digit_mask);
			akku = (short) ((akku >> digit_len) & digit_mask);
		}
		// add carry at position j
		while (akku > 0 && j >= 0) {
			akku = (short) (akku + (short) (this.value[j] & digit_mask));
			this.value[j] = (byte) (akku & digit_mask);
			akku = (short) ((akku >> digit_len) & digit_mask);
			j--;
		}

		return akku != 0;
	}

	/**
	* Addition. Adds other to this number. If this is too small for the result
	* an assertion is thrown.
	* <P>
	* Same as {@link #times_add times_add}{@code (other, 1)} but without the
	* multiplication overhead.
	* <P>
	* Asserts that the size of other is not greater than the size of this.
	* 
	* @param other
	*            Bignat to add
	*/
	public void add(Bignat other) {
		if (add_carry(other)) {
		}
	}

	/**
	* Scaled addition. Add {@code mult * other} to this number. {@code mult}
	* must be below {@link #bignat_base}, that is, it must fit into one digit.
	* It is only declared as a short here to avoid negative numbers.
	* <P>
	* Asserts (overly restrictive) that this and other have the same size.
	* <P>
	* Same as {@link #times_add_shift times_add_shift}{@code (other, 0, mult)}
	* but without the shift overhead.
	* <P>
	* Used in multiplication.
	* 
	* @param other
	*            Bignat to add
	* @param mult
	*            of short, factor to multiply {@code other} with before
	*            addition. Must be less than {@link #bignat_base}.
	*/
	public void times_add(Bignat other, short mult) {
		short akku = 0;
		for (short i = (short) (size - 1); i >= 0; i--) {
			akku = (short) (akku + (short) (this.value[i] & digit_mask) + (short) (mult * (other.value[i] & digit_mask)));

			// if(debug) {
			// System.out.format("TM %d: this %02X other %02X mult %04X " +
			// "akku %04X sub res %04X\n",
			// i,
			// value[i] & 0xff,
			// other.value[i] & 0xff,
			// mult,
			// akku & 0xffff,
			// subtraction_result & 0xffff);
			// }

			this.value[i] = (byte) (akku & digit_mask);
			akku = (short) ((akku >> digit_len) & digit_mask);
		}
		return;
	}

	/**
	* Scaled addition. Adds {@code mult * other * 2^(}{@link #digit_len}
	* {@code * shift)} to this. That is, shifts other {@code shift} digits to
	* the left, multiplies it with {@code mult} and adds then.
	* <P>
	* {@code mult} must be less than {@link #bignat_base}, that is, it must fit
	* into one digit. It is only declared as a short here to avoid negative
	* numbers.
	* <P>
	* Asserts that the size of this is greater than or equal to
	* {@code other.size + shift + 1}.
	* 
	* @param other
	*            Bignat to add
	* @param mult
	*            of short, factor to multiply {@code other} with before
	*            addition. Must be less than {@link #bignat_base}.
	* @param shift
	*            number of digits to shift {@code other} to the left, before
	*            addition.
	*/
	public void times_add_shift(Bignat x, short shift, short mult) {
		// System.out.format("this.size %d other size %d shift %d\n",
		// this.size, other.size, shift);
		short akku = 0;
		short j = (short) (this.size - 1 - shift);
		for (short i = (short) (x.size - 1); i >= 0; i--, j--) {
			akku = (short) (akku + (short) (this.value[j] & digit_mask) + (short) (mult * (x.value[i] & digit_mask)));

			this.value[j] = (byte) (akku & digit_mask);
			akku = (short) ((akku >> digit_len) & digit_mask);
		}
		// add carry at position j
		akku = (short) (akku + (short) (this.value[j] & digit_mask));
		this.value[j] = (byte) (akku & digit_mask);
		// assert no overflow
	}

        /** NOT WORKING YET **/
    public void times_add_shift_Short(Bignat other, short shift, short mult) {
	// 
        short akku = 0;
        short j = (short) (this.size - 1 - shift);
        for (short i = (short) (other.size - 1); i >= 0; i--, j--) {
            akku = (short) ((short) (akku + this.valueShort[j]) + (short) (mult * other.valueShort[i]));

            this.valueShort[j] = akku;
            akku = (short) (akku >> digit_len);
        }
        // add carry at position j
        akku = (short) (akku + this.valueShort[j]);
        this.valueShort[j] = akku;
        // assert no overflow
    }

    /**
    * Multiplication. Stores {@code x * y} in this. To ensure this is big
    * enough for the result it is asserted that the size of this is greater
    * than or equal to the sum of the sizes of {@code x} and {@code y}.
    * 
    * @param x
    *            first factor
    * @param y
    *            second factor
    */
    public void mult(Bignat x, Bignat y) {
        // System.out.format("this size %d x size %d y size %d\n",
        // this.size, x.size, y.size);
        //BigNumber a = new BigNumber((short) 65); // potential to use BigNumber to speedup. But card must support
        //a.add(EC_Utils.TempBuffer65, (short) 0, (short) 65, BigNumber.FORMAT_BCD);
        this.zero();
        for (short i = (short) (y.size - 1); i >= 0; i--) {
            this.times_add_shift(x, (short) (y.size - 1 - i), (short) (y.value[i] & digit_mask));
        }
    }
    
/*    
    // Inspired by : https://github.com/spyrant/algorithms/blob/master/Karatsuba.java
    public void mult2(Bignat x, Bignat y) {    
        // for each digit in bot string from right to left
        for (short i = (short) (y.size - 1); i >= 0; i--) {
            short carryOver_product = 0;				// carryover due to multiplication
            short carryOver_add = 0;					// carryover due to addition 

            // for each digit in top string from right to left
            for (short j = (short) (x.length - 1); j >= 0; j--) {
                // derive product of 2 digits
                short product = bot[i] * x.value[j] + carryOver_product;	// multiply top digit with bottom digit and add with carryover
    //    			System.out.println("top[j] = " + top[j] + ", bot[i] = " + bot[i] + ", carryOver = " + carryOver + ", product = " + product);	// check
                carryOver_product = product / base;					// carry over from product
                product %= base;									// product after forwarding carryover

                // add product to ans[] 
                int ans_index = ans.length - (x.size - j) - offset;	// corresponding index in ans[]
                ans[ans_index] += product + carryOver_add;
                carryOver_add = ans[ans_index] / base;
                ans[ans_index] = ans[ans_index] % base;
            }
            // handle final carryovers
            if (carryOver_product != 0 || carryOver_add != 0) {
                // NOTE: ans[ans_index] is definitely == 0, mathematically (carryOver_product + carryOver_add < base) is guaranteed
                int ans_index = ans.length - (x.length + 1) - offset;
                ans[ans_index] += carryOver_product + carryOver_add;
            }
            offset++;	// update: pad one more '0' to the right of next row
        }    
    }
    */
    /** NOT VERIFIED TO WORK PROPERLY **/
    public void multShort(Bignat x, Bignat y) {
        // System.out.format("this size %d x size %d y size %d\n",
        // this.size, x.size, y.size);
        //BigNumber a = new BigNumber((short) 65); // potential to use BigNumber to speedup. But card must support
        //a.add(EC_Utils.TempBuffer65, (short) 0, (short) 65, BigNumber.FORMAT_BCD);

        this.zero();
        this.prepareShortValueHelper();
        x.prepareShortValueHelper();
        for (short i = (short) (y.size - 1); i >= 0; i--) {
            this.times_add_shift_Short(x, (short) (y.size - 1 - i), (short) (y.value[i] & digit_mask));
        }
        this.restoreFromShortValueHelper();
    }    
    
    public void multRSATrick(Bignat x, Bignat y) {
        multRSATrick(x, y, null);
    }

    public void multRSATrick(Bignat x, Bignat y, byte[] x_pow_2) {
        // Idea of speedup: We need to mutiply x.y where both x and y are 32B
        // (x + y)^2 == x^2 + y^2 + 2xy
        // Fast RSA engine is available (a^b mod n)
        // n can be set bigger than 64B => a^b mod n == a^b
        // [(x + y)^2 mod n] - [x^2 mod n] - [y^2 mod n] => 2xy where [] means single RSA operation
        // 2xy / 2 => result of mult(x,y)
        // Note: mult() is now used during Sign() operation with argument x being value generated during setup => [x^2 mod n] can be precomputed
        
        short xOffset;
        short yOffset;

        
        // x+y
        Util.arrayFillNonAtomic(mult_resultArray, (short) 0, (short) mult_resultArray.length, (byte) 0);
        // We must copy bigger number first
        if (x.size > y.size) {
            // Copy x to the end of mult_resultArray
            xOffset = (short) (mult_resultArray.length - x.size());
            Util.arrayCopyNonAtomic(x.value, (short) 0, mult_resultArray, xOffset, x.size()); 
            if (add(mult_resultArray, xOffset, x.size, y.value, (short) 0, y.size)) {
                xOffset--; mult_resultArray[xOffset] = 0x01;
            }
        }
        else {
            // Copy x to the end of mult_resultArray
            yOffset = (short) (mult_resultArray.length - y.size());
            Util.arrayCopyNonAtomic(y.value, (short) 0, mult_resultArray, yOffset, y.size());
            if (add(mult_resultArray, yOffset, y.size, x.value, (short) 0, x.size)) {
                yOffset--;
                mult_resultArray[yOffset] = 0x01;
            }
        }
        //ISOException.throwIt((short) 0x666);
        

        // ((x+y)^2)
        mult_cipher.doFinal(mult_resultArray, (byte) 0, (short) mult_resultArray.length, mult_resultArray, (short) 0);
        
        // x^2
        if (x_pow_2 == null) {
            // x^2 is not precomputed
            Util.arrayFillNonAtomic(mult_resultArray2, (short) 0, (short) mult_resultArray2.length, (byte) 0);
            xOffset = (short) (mult_resultArray2.length - x.size());
            Util.arrayCopyNonAtomic(x.value, (short) 0, mult_resultArray2, xOffset, x.size());
            mult_cipher.doFinal(mult_resultArray2, (byte) 0, (short) mult_resultArray2.length, mult_resultArray2, (short) 0);
        }
        else {
            // x^2 is precomputed
            if ((short) x_pow_2.length != (short) mult_resultArray2.length) {
                Util.arrayFillNonAtomic(mult_resultArray2, (short) 0, (short) mult_resultArray2.length, (byte) 0);
                xOffset = (short) ((short) mult_resultArray2.length - (short) x_pow_2.length);
            }
            else {
                xOffset = 0;
            }
            Util.arrayCopyNonAtomic(x_pow_2, (short) 0, mult_resultArray2, xOffset, (short) x_pow_2.length);
        }        
        // ((x+y)^2) - x^2
        subtract(mult_resultArray, (short) 0, (short) mult_resultArray.length, mult_resultArray2, (short) 0, (short) mult_resultArray2.length);

        // y^2
        Util.arrayFillNonAtomic(mult_resultArray2, (short) 0, (short) mult_resultArray2.length, (byte) 0);
        yOffset = (short) (mult_resultArray2.length - y.size());
        Util.arrayCopyNonAtomic(y.value, (short) 0, mult_resultArray2, yOffset, y.size());
        mult_cipher.doFinal(mult_resultArray2, (byte) 0, (short) mult_resultArray2.length, mult_resultArray2, (short) 0);

        // {(x+y)^2) - x^2} - y^2
        subtract(mult_resultArray, (short) 0, (short) mult_resultArray.length, mult_resultArray2, (short) 0, (short) mult_resultArray2.length);
        
        // we now have 2xy in mult_resultArray, divide it by 2 => shift by one bit and fill back into this
        short multOffset = (short) ((short) mult_resultArray.length - 1);
        short res = 0;
        short res2 = 0;
        // this.value.length must be different from multOffset, set proper ending condition
        short stopOffset = 0;
        if ((short) (this.value.length) > multOffset) {
            stopOffset = (short) ((short) this.value.length - multOffset); // only part of this.value will be filled
        }
        else {
            stopOffset = 0; // whole this.value will be filled
        }
        Util.arrayFillNonAtomic(this.value, (short) 0, stopOffset, (byte) 0);
        for (short i = (short) ((short) this.value.length - 1); i >= stopOffset; i--) {
            res = (short) (mult_resultArray[multOffset] & 0xff);
            res = (short) (res >> 1);
            res2 = (short) (mult_resultArray[(short) (multOffset - 1)] & 0xff);
            res2 = (short) (res2 << 7);
            this.value[i] = (byte) (short) (res | res2);
            multOffset--;
        }
        
/*        
        //Test output
        short out = (short) 0;
        for (short i = xOffset; i < (short) mult_resultArray.length; i++) {
            this.value[out] = mult_resultArray[i]; out++;
        }
        this.size = out;
*/        
    }
    
    
    public void multKaratsuba(Bignat x, Bignat y) {
        // Idea of speedup: use Karatsuba multiplication algorithm
    }
	/**
	* One digit left shift.
	* <P>
	* Asserts that the first digit is zero.
	*/
	public void shift_left() {
		Util.arrayCopyNonAtomic(this.value, (short) 1, this.value, (short) 0,
				(short) (size - 1));

		value[(short) (size - 1)] = 0;
	}

        
	/**
	* Inefficient modular multiplication.
	* 
	* This bignat is assigned to {@code x * y} modulo {@code mod}. Inefficient,
	* because it computes the modules with {@link #remainder_divide
	* remainder_divide} in each multiplication round. To avoid overflow the
	* first two digits of {@code x} and {@code mod} must be zero (which plays
	* nicely with the requirements for montgomery multiplication, see
	* {@link #montgomery_mult montgomery_mult}).
	* <P>
	* Asserts that {@code x} and {@code mod} have the same size. Argument
	* {@code y} can be arbitrary in size.
	* <P>
	* Included here to make it possible to compute the squared <a
	* href="package-summary.html#montgomery_factor">montgomery factor</a>,
	* which is needed to montgomerize numbers before montgomery multiplication.
	* Until now this has never been used, because the montgomery factors are
	* computed on the host and then installed on the card. Or numbers are
	* montgomerized on the host already.
	* 
	* @param x
	*            first factor, first two digits must be zero
	* @param y
	*            second factor
	* @param mod
	*            modulus, first two digits must be zero
	*/
	public void mult_mod(Bignat x, Bignat y, Bignat mod) {
		this.zero();
		for (short i = 0; i < y.size; i++) {

			this.shift_left();

			this.times_add(x, (short) (y.value[i] & digit_mask));

			this.remainder_divide(mod, null);
		}
		return;
	}

	/**
	* One digit right shift. Asserts that the least significant digit is zero.
	*/
	public void shift_right() {
            Util.arrayCopyNonAtomic(this.value, (short)0, this.value, (short)1, 
                         (short)(size -1));
            value[0] = 0;
	}
        public void shiftBytes_right(short numBytes) {
            // Move whole content by numBytes offset
            Util.arrayCopyNonAtomic(this.value, (short) 0, fastResizeArray, (short) 0, (short) (this.value.length));
            Util.arrayCopyNonAtomic(fastResizeArray, (short) 0, this.value, numBytes, (short) ((short) (this.value.length) - numBytes));
            Util.arrayFillNonAtomic(this.value, (short) 0, numBytes, (byte) 0);
        }

	// Montgomery multiplication as I understood it:
	// The aim is to compute x * y modulo mod without allocating
	// more memory and without taking the modulus in every
	// multiplication round. Therefore one chooses b^n > mod,
	// where b is the base that is used in the multiplication and
	// n is the maximal number of digits. For pen and paper
	// multiplication usually b = 10. Here b = 256, because
	// one short is one digit here. Note that also x and y must
	// be less than b^n. Because everything is finally taken
	// modulo mod one works of course with b^n modulo mod.
	// This b^n modulo mod is called the Montgomery factor mont_fak.
	//
	// Now instead of computing x * y one first computes
	// x' = x * mont_fak and similarly for y. This is called
	// montgomerization.
	// Now one computes (x' * y' / mont_fac) modulo mod.
	// Note that the result is again of the form z * mont_fac, where
	// z = x * y denotes the real result.
	// The computation (x' * y' / mont_fac) modulo mod
	// can easily be done in (n+2) shorts by shifting the akkumulator
	// one digit to the right after each multiplication round
	// (and ensuring that there are presicely n multiplication rounds).
	// Only one modulo operation is needed at the end.
	// The only remaining problem is that the right shift,
	// which is in fact a division by the base b, must not change the
	// the remainder modulo mod. Therefore one adds a Montgomery
	// correction to the akkumulator after each multilication round.
	// This Montgomery correction will be chosen such that the
	// akkumulator is divisible by the base b (ie. the last digit is
	// zero). The Montgomery correction exists if the modulus is odd,
	// which we take here for granted. The Montgomery correction is
	// computed with the inverses modulo 256 of the last digit of mod,
	// see class Inverse_mod_256.

	/**
	* Montgomery multiplication (special modular multiplication). Stores
	* {@code x} * {@code y} / {@code mont_fac} (modulo {@code mod}) in this
	* bignat, where {@code mont_fac} is the <a
	* href="package-summary.html#montgomery_factor">montgomery factor</a> for
	* {@code mod} and {@code this.size}. Computes the modular montgomerized
	* product if the arguments are montgomerized.
	* <P>
	* 
	* Asserts that this and the arguments all have the same size. Further the
	* first two digits of {@code x}, {@code y} and {@code mod} must be zero. As
	* unchecked assumption {@code mod} must be odd. Strange things will happen
	* for even moduli (Note that with the standard procedure to obtain a
	* {@link Modulus}, namely by initializing and sending a
	* {@link Host_modulus} to the card, it is impossible to obtain an even
	* modulus).
	* <P>
	* The requirement for an odd modulus comes from the following. The
	* dividision by {@code mont_fac} is actually done by shifting the
	* akkumulator one digit to the right after each multiplication round.
	* Because the first two digits of all arguments are zero, we do
	* {@link #size} -2 multiplication rounds, that is, with one shift each
	* round, we precisely divide by 2^({@link #digit_len} * ({@code size} -
	* 2)), ie, by {@code mont_fac}. Before the right shift the least
	* significant digit must be zero, otherwise we compute wrong results. To
	* get a zero there we just add x * {@code mod}, where x is precisely that
	* factor that makes the last digit of the sum zero. Assume short digits
	* (BIGNAT_USE_short) and that the last digit of the akkumulator is 255.
	* Then we need to add x * {@code mod} such that x * {@code mod} = 1 (modulo
	* 256). That is, x must be the modular inverse of {@code mod} modulo 256.
	* If the last digit is 254 we simply add 2 * x * {@code mod}, which equals
	* 2 (modulo 256). The required modular inverse exists precisely when
	* {@code mod} and 256 (or {@link #bignat_base}, more generally) are
	* coprime, which happens precisely when {@code mod} is odd.
	* <P>
	* With some computations one can show that after the right shift the
	* akkumulator always fits into {@link #size} -1 digits without the need of
	* computing remainders modulo {@code mod} in between. To ensure the result
	* fits in {@link #size} -2 digits and is actually less then {@code mod} a
	* final {@link #remainder_divide remainder_divide} is done.
	* 
	* @param x
	*            first factor, first two digits must be zero
	* @param y
	*            second factor, first two digits must be zero
	* @param mod
	*            modulus, must be odd, first two digits must be zero
	* @CPP The following preprocessor directives select variants of this
	*      method: <a
	*      href="../../../overview-summary.html#OPT_DOUBLE_ADD">OPT_DOUBLE_ADD
	*      </a>, <a
	*      href="../../../overview-summary.html#OPT_SKIP_DEVIDE">OPT_SKIP_DEVIDE
	*      </a>, <a
	*      href="../../../overview-summary.html#MONTGOMERY_MULT_SHORTCUT"
	*      >MONTGOMERY_MULT_SHORTCUT</a>
	* 
	* 
	*      Both optimizations produced only almost unnoticably effects in my
	*      tests.
	*/

	/**
	* Modular power. Computes {@code base^exponent (modulo
	* modulus)} and stores the result in this bignat. {@code base} must be
	* montgomerized and {@code exponent} must not. The result will be
	* montgomerized. Needs a temporary for the computation and a montgomerized
	* 1 (which is equal to the <a
	* href="package-summary.html#montgomery_factor">montgomery factor</a> and
	* can be found, for instance, in {@link Host_modulus#mont_fac}) to
	* initialize the akkumulator.
	* <P>
	* 
	* Asserts that {@code this}, {@code base}, {@code modulus},
	* {@code mont_one} and {@code temp} all have the same size. The size of the
	* exponent can be arbitrary. {@code base} and {@code modulus} must fulfill
	* the preconditions of montgomery multiplication, that is, there first two
	* digits must be zero.
	* <P>
	* Uses the repeated squaring method internally without further
	* optimizations (so it pays off if there are not too many leading zeros in
	* the exponent).
	* 
	* @param base
	*            montgomerized base
	* @param exponent
	*            exponent (not montgomerized)
	* @param modulus
	*            the modulus
	* 
	* @param mont_one
	*            1, montgomerized (which equals the <a
	*            href="package-summary.html#montgomery_factor">montgomery
	*            factor</a>, see {@link Host_modulus#mont_fac})
	* 
	* @param temp
	*            a temporary, different from all other arguments.
	*/
	public void prime_mod_exp(byte[] exponent_Bn, byte[] modulo_prime_Bn) {
		byte[] result_arr = new byte[(short)modulo_prime_Bn.length]; //JCSystem.makeTransientByteArray((short)64, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
		
		Cipher cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
	
	    RSAPrivateKey privateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, (short)256, false);
	    RSAPublicKey publicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
	
	    publicKey.setExponent(exponent_Bn, (short) 0,(short) exponent_Bn.length);
	    publicKey.setModulus(modulo_prime_Bn, (short) 0,(short) modulo_prime_Bn.length);
	            
	    cipher.init(publicKey, Cipher.MODE_ENCRYPT);
	    cipher.doFinal(this.as_byte_array(), (short) 0, (short) this.as_byte_array().length, result_arr, (short) 0);
	    
	    this.from_byte_array((short)result_arr.length, (short)0, result_arr, (short)0);
	}
        
        

	/**
	* 
	* Division by 2. Shifts all bits one to the right.
	*/
	public void div_2() {
		short carry = 0;
		for (short i = 0; i < this.size; i++) {
			if ((this.value[i] & 0x01) == 0) {
				this.value[i] = (byte) (((this.value[i] & digit_mask) >> 1) | carry);
				carry = 0;
			} else {
				this.value[i] = (byte) (((this.value[i] & digit_mask) >> 1) | carry);
				carry = digit_first_bit_mask;
			}
		}
	}


	/**
	* performs a modular division by 2 The output is of operation is saved in
	* the input itself
	* 
	* @param input
	* @param inOffset
	* @param inLength
	*/
	public static void modular_division_by_2(byte[] input, short inOffset,
			short inLength, byte[] modulos, short modOffset, short modLength) {
		short carry = 0;
		short digit_mask = 0xff;
		short digit_first_bit_mask = 0x80;
		short lastIndex = (short) (inOffset + inLength - 1);

		short i = inOffset;
		if ((byte) (input[lastIndex] & 0x01) != 0) {
			if (Bignat.add(input, inOffset, inLength, modulos, modOffset,
					modLength)) {
				carry = digit_first_bit_mask;
			}
		}

		for (; i <= lastIndex; i++) {
			if ((input[i] & 0x01) == 0) {
				input[i] = (byte) (((input[i] & digit_mask) >> 1) | carry);
				carry = 0;
			} else {
				input[i] = (byte) (((input[i] & digit_mask) >> 1) | carry);
				carry = digit_first_bit_mask;
			}
		}
	}
	/**
	* 
	* Modular division by 2. This method computes {@code x modulo
	* mod} on the assumption that {@code 2x modulo mod} is in this bignat
	* before calling this method.
	* <P>
	* 
	* The most significant bit of the modulus {@code mod} (and therefore also
	* the most significant bit of this bignat) must be zero, otherwise an
	* assertion might get triggered inside {@link #add add}.
	* 
	* @param mod
	*            modulus
	*/

	// ########################################################################
	// APDU_Serializable interface
	//

	/**
	* Compatibility check for the OV-chip protocol layer. See <a
	* href="../util/APDU_Serializable.html#apdu_compatibility"> the
	* compatibility check explanations</a> and also
	* {@link ds.ov2.util.APDU_Serializable#is_compatible_with
	* APDU_Serializable.is_compatible_with}.
	* <P>
	* 
	* Bignat objects are compatible to Bignat's and {@link APDU_BigInteger
	* APDU_BigInteger's} of the same size.
	* 
	* @param o
	*            actual argument or result
	* @return true if {@code o} is either a Bignat or an
	*         {@link APDU_BigInteger} of the same size.
	*/
	public boolean is_compatible_with(Object o) {
		if (o instanceof Bignat) {
			return this.size() == ((Bignat) o).size();
		}
		return false;
	}

	/**
	* Serialization of this object for the OV-chip protocol layer. See
	* {@link ds.ov2.util.APDU_Serializable#to_short_array
	* APDU_Serializable.to_short_array}.
	* 
	* @param len
	*            available space in {@code short_array}
	* @param this_index
	*            number of shorts that have already been written in preceeding
	*            calls
	* @param short_array
	*            data array to serialize the state into
	* @param short_index
	*            index in {@code short_array}
	* @return the number of shorts actually written, except for the case where
	*         serialization finished by writing precisely {@code len} shorts,
	*         in this case {@code len + 1} is returned.
	*/
	public short to_byte_array(short len, short this_index,
			byte[] byte_array, short short_index) {
		short max = (short) (this_index + len) <= this.size ? len
				: (short) (this.size - this_index);
		Util.arrayCopyNonAtomic(value, this_index, byte_array, short_index, max);
		if ((short) (this_index + len) == this.size)
			return (short) (len + 1);
		else
			return max;
	}
	


	public void from_short(short s) {
		//from_byte_array((short) shortToByteArray(s).length, (short) 0, shortToByteArray(s), (short) 0);
		value[(short) (size - 2)] = (byte)(s & 0xff);
		value[(short) (size - 1)] = (byte)((s >> 8) & 0xff);
	}
	
	
	/**
	* Deserialization of this object for the OV-chip protocol layer. See
	* {@link ds.ov2.util.APDU_Serializable#from_short_array
	* APDU_Serializable.from_short_array}.
	* 
	* @param from_array_length
	*            available data in {@code from_array}
	* @param this_offset
	*            offset where data should be stored 
	* @param from_array
	*            data array to deserialize from
	* @param from_array_offset
	*            offset in {@code from_array}
	* @return the number of shorts actually read, except for the case where
	*         deserialization finished by reading precisely {@code len} shorts,
	*         in this case {@code len + 1} is returned.
	*/

    public short from_byte_array(short from_array_length, short this_offset,
                                 byte[] from_array, short from_array_offset) {
        short max = 
            (short)(this_offset + from_array_length) <= this.size ? 
                      from_array_length : (short)(this.size - this_offset);
        Util.arrayCopyNonAtomic(from_array, from_array_offset, value, this_offset, max);
        if((short)(this_offset + from_array_length) == this.size)
            return (short)(from_array_length + 1);
        else
            return max;
    }

    /**
     * Set content of Bignat internal array
     *
     * @param this_offset offset where data should be stored
     * @param from_array data array to deserialize from
     * @param from_array_length available data in {@code from_array}
     * @param from_array_offset offset in {@code from_array}
     * @return the number of shorts actually read, except for the case where
     * deserialization finished by reading precisely {@code len} shorts, in this
     * case {@code len + 1} is returned.
     */    
    public short set_from_byte_array(short this_offset, byte[] from_array, short from_array_offset, short from_array_length) {
        return from_byte_array(from_array_length, this_offset, from_array, from_array_offset);
    }
    	
    
    

    /* 20170115 unused
	public static Bignat valueOf(short size, byte b) {
		Bignat tmp = new Bignat(size, false);
		tmp.setLastByte(b);
		return tmp;
	}
	
	public static Bignat RandomBignat(short size) {
	byte[] tmp_array = new byte[size];
		RandomData rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		rng.generateData(tmp_array, (short) 0, (short) size);
		
		Bignat rnd_bn = new Bignat((short)32, false);
		rnd_bn.zero();
	rnd_bn.from_byte_array((short) size, (short) 0, tmp_array, (short) 0); 
	return rnd_bn;
	}
	
	public static Bignat RandomBignat() {
		return RandomBignat(Parameters.RND_SIZE);
	}
        
    
    public static Bignat PrivKeyToBignat(ECPrivateKey key) {
	byte[] TempBuffer32 = new byte[32];
	
	if (key.getSize()!=256)//in bits
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	
        short len = key.getS(TempBuffer32, (short) 0);
        
        Bignat bn = new Bignat((short)(key.getSize()/8), false);
	bn.zero();
	bn.from_byte_array((short)TempBuffer32.length, (short)(0), TempBuffer32, (short)0);
	return bn;
    }
    */
/*    
    public static ECPrivateKey BignatToPrivKey(Bignat bn) {
        
        KeyPair disposable_pair	= SecP256r1.newKeyPair();
	ECPrivateKey disposable_priv = (ECPrivateKey) disposable_pair.getPrivate(); 
	disposable_pair.genKeyPair();
	disposable_priv.setS(bn.as_byte_array(), (short) 0, (short) bn.as_byte_array().length);
	return disposable_priv;
    }
*/        

	
}