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
import java.nio.ByteBuffer ;

public class SimpleApplet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET               = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_SETPIN                     = (byte) 0x50;
    final static byte INS_VERIFYPIN                  = (byte) 0x51;
    final static byte INS_SIGNDATA                   = (byte) 0x52;
    final static byte INS_RETURNDATA                 = (byte) 0x53;    
    final static byte INS_SIGNTIME                   = (byte) 0x54; 
    final static byte INS_GETPASSWORD                = (byte) 0x55; 
        
    final static short ARRAY_LENGTH                  = (short) 0xff;
    
    final static short SW_PIN_VERIFICATION_REQUIRED  = (short) 0x6301;
    final static short SW_PIN_VERIFICATION_FAILED    = (short) 0x6302;
    
    private   OwnerPIN       m_pin = null;
    private   Signature      m_sign = null;
    private   KeyPair        m_keyPair = null;
    private   Key            m_privateKey = null;
    private   Key            m_publicKey = null;
    private   AESKey         m_aesKey = null;
    private   Cipher         m_encryptCipher_CBC = null;
    private   Cipher         m_decryptCipher_CBC = null;
    
    private   byte           m_dataArray[] = null;
    
    private   byte           PIN_VALIDATED = 0;
    final     private   int  PIN_TRY_LIMIT = 5;
    final     private   int  PIN_SIZE = 4;
    private   byte           m_ramArray[] = null;
    
    private static byte DEFAULT_USER_PIN[] = {(byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34};
    
    private static byte DEFAULT_USER_PASSWORD[] = {(byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34};
    private static     byte[] AESkey = {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06,(byte) 0x07,
                  (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E,(byte) 0x0F};
      
    private byte[] m_SigningTime ; 
            
    protected SimpleApplet(byte[] buffer, short offset, byte length)
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

            m_dataArray = new byte[ARRAY_LENGTH];
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);

            m_pin = new OwnerPIN((byte) PIN_TRY_LIMIT, (byte) PIN_SIZE);
            m_pin.update(DEFAULT_USER_PIN, (byte) 0, (byte) PIN_SIZE);

            // CREATE AES KEY OBJECT
            m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            // CREATE OBJECTS FOR CBC CIPHERING
            m_encryptCipher_CBC = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            m_decryptCipher_CBC = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            //        m_encryptCipher_CBC = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            //        m_decryptCipher_CBC = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            //  TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArray = new byte[260];
            m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);
            // SET KEY VALUE
            m_aesKey.setKey(m_ramArray, (short) 0);

            // INIT CIPHERS WITH NEW KEY
            //CBC
            m_encryptCipher_CBC.init(m_aesKey, Cipher.MODE_ENCRYPT);
            m_decryptCipher_CBC.init(m_aesKey, Cipher.MODE_DECRYPT);
        
            // CREATE RSA KEYS AND PAIR
            m_keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1024);
            
            m_sign = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
            
            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);
            m_SigningTime = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
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
        new SimpleApplet (bArray, bOffset, bLength);
    }

    /**
     * Select method returns true if applet selection is supported.
     * @return boolean status of selection.
     */
    public boolean select()
    {
        // <PUT YOUR SELECTION ACTION HERE>
        
      return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect()
    {

        // <PUT YOUR DESELECTION ACTION HERE>

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
                case INS_SIGNDATA: 
                        Sign(apdu); 
                        break;
                case INS_SIGNTIME: 
                        SignTime(apdu); 
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
    
    void GetPassword(APDU apdu) {
      
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      short     i;

      // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
      Util.arrayCopyNonAtomic(DEFAULT_USER_PASSWORD, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);
      
      // SEND OUTGOING BUFFER
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
        
    }
    
    
    
    // VERIFY PIN
    void VerifyPIN(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      m_aesKey.setKey(AESkey, (short) 0);  
     // m_encryptCipher_CBC.init(m_aesKey, Cipher.MODE_ENCRYPT);
      m_decryptCipher_CBC.init(m_aesKey, Cipher.MODE_DECRYPT);
      
      //  m_encryptCipher_CBC.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);
     m_decryptCipher_CBC.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);
     Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);
     
      // VERIFY PIN
      if (m_pin.check(apdubuf, ISO7816.OFFSET_CDATA, (byte) 4) == false)
         ISOException.throwIt(SW_PIN_VERIFICATION_FAILED);
                
    }

    // SET PIN
    void SetPIN(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // SET NEW PIN
      m_pin.update(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen);
    }

    void ReturnData(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // RETURN INPU DATA UNCHANGED
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }

    void SignTime(APDU apdu) {
            
     byte[]    apdubuf = apdu.getBuffer();
     short     dataLen = apdu.setIncomingAndReceive();
     short     Len = 8;

     // COPY time DATA INTO OUTGOING BUFFER
     Util.arrayCopyNonAtomic(m_SigningTime, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, Len);

     // SEND OUTGOING BUFFER
     apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, Len);     
     
    }
    
    private byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }
    
    void Sign(APDU apdu) {
     
     long startTime = System.currentTimeMillis();
     //First check for PIN validation
     if(!this.m_pin.isValidated())
         ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        
     byte[]    apdubuf = apdu.getBuffer();
     short     dataLen = apdu.setIncomingAndReceive();
     short     signLen = 0;
     
     /*
     for(int i=0; i<16; i++)
     {
          System.out.printf("0x%02X\t", apdubuf[i+5]);
     }
     */
     
     // STARTS KEY GENERATION PROCESS
     m_keyPair.genKeyPair();

     // OBTAIN KEY REFERENCES
     m_publicKey = m_keyPair.getPublic();
     m_privateKey = m_keyPair.getPrivate();

     // INIT WITH PRIVATE KEY
     m_sign.init(m_privateKey, Signature.MODE_SIGN);

     // SIGN INCOMING BUFFER
     signLen = m_sign.sign(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen, m_ramArray, (byte) 0);

     // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
     Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, signLen);

     // SEND OUTGOING BUFFER
     apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, signLen);
     
     long endTime = System.currentTimeMillis();     
     
     //System.out.println(endTime-startTime);
     this.m_SigningTime = longToBytes(endTime - startTime) ;
     
    }
}

