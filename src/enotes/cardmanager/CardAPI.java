/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package enotes.cardmanager;

import enotes.EnotesException;
import java.security.Key;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.ResponseAPDU;

/**
 * @author tbabej
 */
public class CardAPI {
    
    boolean SIMULATOR_ACTIVE = true;
    CardManager cardManager = new CardManager();
    
    // So far hardcoded AES key
    private static byte[] AES_KEY = {
        (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03,
        (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
        (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B,
        (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F
    };
    
    private static final byte APPLET_AID[] = {
        (byte) 0x65, (byte) 0x4e, (byte) 0x6f, (byte) 0x74, (byte) 0x65,
        (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74
    };
    
    private static final byte[] SELECT_ENOTESAPPLET = {
        (byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, 
        (byte) 0x65, (byte) 0x4e, (byte) 0x6f, (byte) 0x74, (byte) 0x65,
        (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    
    // API state
    
    private boolean m_card_connected = false;

    public CardAPI(){
        if (SIMULATOR_ACTIVE){
            byte[] installData = new byte[10];
            cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, eNoteApplet.class); 
        }
    }
    
    void autoConnect() throws EnotesException
    {
        if (!m_card_connected)
            ConnectCard();
    }
        
    // Performs Encryption
    public static byte[] encrypt(byte[] plainText, byte[] encKey) throws Exception 
    {
            Key key = new SecretKeySpec(encKey, "AES");
            Cipher chiper = Cipher.getInstance("AES/ECB/NoPadding");
            chiper.init(Cipher.ENCRYPT_MODE, key);
            byte[] encVal = chiper.doFinal(plainText);
            return encVal;
    }
    
    // Performs decryption
    public static byte[] decrypt(byte[] encryptedText, byte[] decKey) throws Exception 
    {
            Key key = new SecretKeySpec(decKey, "AES");
            Cipher chiper = Cipher.getInstance("AES/ECB/NoPadding");
            chiper.init(Cipher.DECRYPT_MODE, key);
            byte[] decValue = chiper.doFinal(encryptedText);
            return decValue;
    }
    
    public byte[] send(byte[] apdu) throws EnotesException
    {
        return send(apdu, true);
    }
    
    public byte[] send(byte[] apdu, boolean checkSuccess) throws EnotesException{
        byte[] result;
        autoConnect();
        
        try {
            if (SIMULATOR_ACTIVE) {
                result = cardManager.sendAPDUSimulator(apdu);
            } else {
                ResponseAPDU response = cardManager.sendAPDU(apdu);                
                result = response.getBytes();
            }
        }
        catch (Exception exception) {
            // TODO: Do something better
            System.out.println("An exception occured: " + exception);
            throw new EnotesException("APDU send operation failed.");
        }
        
        if (checkSuccess){
            if(result[result.length-2] == (byte) 0x63 && result[result.length-1] == (byte) 0x01){
                System.out.println("APDU failed result: " + cardManager.bytesToHex(result));
                throw new EnotesException("Card PIN verification required.");            
            }
            
            if(result[result.length-2] == (byte) 0x63 && result[result.length-1] == (byte) 0x02){
                System.out.println("APDU failed result: " + cardManager.bytesToHex(result));
                throw new EnotesException("Card PIN verification failed.");            
            }
            
            if(result[result.length-2] != (byte) 0x90 || result[result.length-1] != (byte) 0x00){
                System.out.println("APDU failed result: " + cardManager.bytesToHex(result));
                throw new EnotesException("APDU finished with non-success result.");
            }
        }
        
        // It seems that the APDU result is ok, let's remove the status suffix bytes
        return Arrays.copyOfRange(result, 0, result.length-2);
    }
    
    public boolean checkPIN(char[] pin)
    {
        try{            
           //Validate PIN
            short additionalDataLen1 = 16;
            byte apdu[] = new byte[CardManager.HEADER_LENGTH + additionalDataLen1];

            apdu[CardManager.OFFSET_CLA] = (byte) 0xB0;
            apdu[CardManager.OFFSET_INS] = (byte) 0x51;
            apdu[CardManager.OFFSET_P1] = (byte) 0x00;
            apdu[CardManager.OFFSET_P2] = (byte) 0x00;
            apdu[CardManager.OFFSET_LC] = (byte) additionalDataLen1;
          
            // Support only 4-byte PINs
            if(pin.length != 4){
                System.out.println("Incorrect PIN length");
                return false;                
            }
            
            // Pad the PIN to 16 bytes and encrypt it
            byte[] bytePIN = new byte[16];    
            for(int i=0; i<16; i++){
                if(i<4)
                    bytePIN[i]= (byte) pin[i];
                else
                    bytePIN[i]= (byte) 0;
            }
            byte[] encPIN = encrypt(bytePIN, AES_KEY);

            System.arraycopy(encPIN, 0, apdu, 5, encPIN.length);
            
            System.out.println("---PIN Validation Started---");                                    
            send(apdu); 
            System.out.println("---PIN Validation Completed---") ;          
            
        }
        catch(Exception ex) {
            System.out.println("Exception : " + ex);
        }
        return true;
    }

    public void setPIN() throws EnotesException
    {
        autoConnect();
        byte apdu_setPIN[]={(byte) 0xB0,(byte) 0x50,(byte) 0x00,(byte) 0x00,(byte) 0x04,
                  (byte) 0x30,(byte) 0x31,(byte) 0x30,(byte) 0x31};
        send(apdu_setPIN);           
    }

    public void ConnectCard() throws EnotesException {
        if (!m_card_connected)
        {
            if (!SIMULATOR_ACTIVE)
            {
                try {
                    if (cardManager.ConnectToCard())
                    {
                        send(SELECT_ENOTESAPPLET);
                        m_card_connected = true;
                    }
                    else
                        throw new EnotesException("Unable to connect the card.");
                    
                } catch (Exception ex) {
                    System.out.println("Error during card connection: " + ex);
                    throw new EnotesException("Unable to connect the card.", ex);
                }
            }
            else {
                m_card_connected = true;
            }
        }
    }
    
    public void DisconnectFromCard() throws Exception
    {
        cardManager.DisconnectFromCard();
        m_card_connected = false;
    }
 
    public String GetPasswordFromCard() throws EnotesException
    {
        autoConnect();
        
        // Ask for the password
        short additionalDataLen1 = 16;
        byte apdu[] = new byte[CardManager.HEADER_LENGTH + additionalDataLen1];

        apdu[CardManager.OFFSET_CLA] = (byte) 0xB0;
        apdu[CardManager.OFFSET_INS] = (byte) 0x55;
        apdu[CardManager.OFFSET_P1] = (byte) 0x00;
        apdu[CardManager.OFFSET_P2] = (byte) 0x00;
        apdu[CardManager.OFFSET_LC] = (byte) additionalDataLen1;

        // Obtain the reponse
        byte[] response = send(apdu);
        
        // Try to extract actual password from it
        try{
            response = decrypt(response, AES_KEY);
        }
        catch(Exception ex){
            System.out.println("Exception during password decryption: " + ex);
            throw new EnotesException("Password decryption failed.", ex);
        }
        
        System.out.println("Password Retreived Sucessfully!!");
        return Arrays.toString(response);
    }
}
