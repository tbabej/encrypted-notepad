/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package enotes.cardmanager;

/**
 *
 * @author dilip
 */
/*
 * PACKAGEID: 4C 61 62 61 6B
 * APPLETID: 4C 61 62 61 6B 41 70 70 6C 65 74
 */
//package applets;

/*
 * Imported packages
 */
// specific import for Javacard API access
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class eNoteApplet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET               = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_SETPIN                     = (byte) 0x50;
    final static byte INS_VERIFYPIN                  = (byte) 0x51;
    final static byte INS_RETURNDATA                 = (byte) 0x53;    
    final static byte INS_GETPASSWORD                = (byte) 0x55; 
        
    final static short ARRAY_LENGTH                  = (short) 0xff;
    
    final static short SW_PIN_VERIFICATION_REQUIRED  = (short) 0x6301;
    final static short SW_PIN_VERIFICATION_FAILED    = (short) 0x6302;
    
    private   OwnerPIN       m_pin = null;
    private   AESKey         m_aesKey = null;
    private   RandomData     m_secureRandom = null;
    private   Cipher         m_encryptCipher = null;
    private   Cipher         m_decryptCipher = null;
    
    private byte             m_dataArray[] = null;
    private byte             m_ramArray[] = null;
    
    private static final short  PIN_TRY_LIMIT = 5;
    private static final short  PIN_SIZE = 4;
     
    private static final byte DEFAULT_USER_PIN[] = {
        (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34
    };
    
    private static final byte[] AES_KEY = {
        (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03,
        (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
        (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B,
        (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F
    };

      
    protected eNoteApplet(byte[] buffer, short offset, byte length)
    {
        // data offset is used for application specific parameter.
        // initialization with default offset (AID offset).
        short dataOffset = offset;
        boolean isOP2 = false;

        if(length > 9) {
            // Install parameter detail. Compliant with OP 2.0.1.

            // | size | content
            // |------|---------------------------
            // |  1   | [AID_Length]
            // | 5-16 | [AID_Bytes]
            // |  1   | [Privilege_Length]
            // | 1-n  | [Privilege_Bytes] (normally 1Byte)
            // |  1   | [Application_Proprietary_Length]
            // | 0-m  | [Application_Proprietary_Bytes]

            // shift to privilege offset
            dataOffset += (short)( 1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short)( 1 + buffer[dataOffset]);

            // go to proprietary data
            dataOffset++;

            m_pin = new OwnerPIN((byte) PIN_TRY_LIMIT, (byte) PIN_SIZE);
            m_pin.update(DEFAULT_USER_PIN, (byte) 0, (byte) PIN_SIZE);
            
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

            //  TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArray = new byte[260];
            m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);            
            
            // CREATE AES KEY OBJECT
            m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            m_aesKey.setKey(AES_KEY, (short) 0);

            // CREATE OBJECTS FOR CBC CIPHERING
            m_encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            m_decryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);

            m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
            m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);

            // update flag
            isOP2 = true;

        } else {
           // <IF NECESSARY, USE COMMENTS TO CHECK LENGTH >
           // if(length != <PUT YOUR PARAMETERS LENGTH> )
           //     ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH + length));
       }
        // register this instance
          register();
    }

    /**
     * Method installing the applet.
     * @param bArray the array constaining installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        // applet  instance creation 
        new eNoteApplet (bArray, bOffset, bLength);
    }

    /**
     * Select method returns true if applet selection is supported.
     * @return boolean status of selection.
     */
    public boolean select()
    {
      return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect()
    {
        return;
    }

    /**
     * Method processing an incoming APDU.
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes defined by ISO 7816-4
     */
    public void process(APDU apdu) throws ISOException
    {
        // get the APDU buffer
        byte[] apduBuffer = apdu.getBuffer();
        //short dataLen = apdu.setIncomingAndReceive();
        //Util.arrayCopyNonAtomic(apduBuffer, (short) 0, m_dataArray, m_apduLogOffset, (short) (5 + dataLen));
        //m_apduLogOffset = (short) (m_apduLogOffset + 5 + dataLen);

        // ignore the applet select command dispached to the process
        if (selectingApplet())
            return;

        // APDU instruction parser
        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
            
            switch ( apduBuffer[ISO7816.OFFSET_INS] ) {
                case INS_SETPIN: 
                        SetPIN(apdu); 
                        break;
                case INS_VERIFYPIN: 
                        VerifyPIN(apdu); 
                        break;
                case INS_RETURNDATA: 
                        ReturnData(apdu); 
                        break;    
                case INS_GETPASSWORD:
                        GetPassword(apdu);
                        break;
                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                    break ;                        

            }
        }
        else 
            ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }
    
    void CheckPINValidated() {
        if(!this.m_pin.isValidated())
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
    }
    
    void GetPassword(APDU apdu) {
      
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      
      CheckPINValidated();
      
      // If no password is stored, generate it and store it
      if (m_dataArray == null)
      {
          m_dataArray = new byte[ARRAY_LENGTH];
          m_secureRandom.generateData(m_dataArray, (short) 0, (short) 16);
      }

      // Copy the password to the RAM array
      Util.arrayCopyNonAtomic(m_dataArray, (short) 0, m_ramArray, (short) 0, (byte) 16);      
      
      // Copy the encrypted version to the APDU buffer
      m_encryptCipher.doFinal(m_dataArray, (short) 0, (short) 16, m_ramArray, (short) 0);     
      Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (byte) 16);
      
      // Send the buffer back
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }

    // VERIFY PIN
    void VerifyPIN(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      //  m_encryptCipher_CBC.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);
     m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);
     Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (byte)4);
     
      // VERIFY PIN
      if (m_pin.check(apdubuf, ISO7816.OFFSET_CDATA, (byte) 4) == false)
         ISOException.throwIt(SW_PIN_VERIFICATION_FAILED);
    }

    // SET PIN
    void SetPIN(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      
      CheckPINValidated();
      
      // SET NEW PIN
      m_pin.update(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen);
    }

    void ReturnData(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // RETURN INPU DATA UNCHANGED
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }    
}

