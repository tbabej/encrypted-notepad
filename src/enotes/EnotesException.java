/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package enotes;

/**
 *
 * @author tbabej
 */

public class EnotesException extends Exception {

    public EnotesException(String message) {
        super(message);
    }

    public EnotesException(String message, Throwable throwable) {
        super(message, throwable);
    }

}