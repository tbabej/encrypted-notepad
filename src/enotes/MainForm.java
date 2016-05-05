/*
 * (c) 2009.-2011. Ivan Voras <ivoras@fer.hr>
 * Released under the 2-clause BSDL.
 */


/*
 * fmain.java
 *
 * Created on 2010.01.15, 12:44:24
 */

package enotes;

import enotes.cardmanager.CardAPI;
import enotes.doc.DocMetadata;
import enotes.doc.DocException;
import enotes.doc.Doc;
import enotes.doc.DocPasswordException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.event.CaretEvent;
import javax.swing.event.CaretListener;
import javax.swing.filechooser.FileFilter;
import javax.swing.text.Document;
import javax.swing.text.Element;

import enotes.cardmanager.eNoteApplet;
import enotes.cardmanager.CardManager;



/**
 *
 * @author ivoras
 */
public class MainForm extends javax.swing.JFrame {
    
    /**************************** Java Card *****/
    static CardAPI cardAPI = new CardAPI();
    UserPINDialog pinDialog = new UserPINDialog();
    
    /*******************************************************************/
    static final int OPT_SAVE = 1;
    static final int OPT_NOSAVE = 2;
    static final int OPT_CANCEL = 3;

    static final int WHYSAVE_SAVE = 1;
    static final int WHYSAVE_SAVEAS = 2;
    static final int WHYSAVE_CLOSE = 3;

    private DocMetadata docm = new DocMetadata();
    private WordSearcher searcher;
    int tp_line, tp_col;

    /** Creates new form fmain */
    public MainForm() {
        initComponents();
        updateTitle();
        tp.addCaretListener( new CaretListener(){
          public void caretUpdate(CaretEvent e ){
              Document doc = tp.getDocument();
                Element root = doc.getDefaultRootElement();
                int dot = e.getDot();
                tp_line = root.getElementIndex( dot );
                tp_col = dot - root.getElement( tp_line ).getStartOffset();
                updateCaretStatus();
            }
          } );
        updateCaretStatus();
        searcher = new WordSearcher(tp);
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        lbCaret = new javax.swing.JLabel();
        jPanel2 = new javax.swing.JPanel();
        tfFind = new javax.swing.JTextField();
        btFind = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        tp = new javax.swing.JTextPane();
        jMenuBar1 = new javax.swing.JMenuBar();
        jMenu1 = new javax.swing.JMenu();
        miNew = new javax.swing.JMenuItem();
        miOpen = new javax.swing.JMenuItem();
        miSave = new javax.swing.JMenuItem();
        miSaveAs = new javax.swing.JMenuItem();
        jSeparator1 = new javax.swing.JSeparator();
        miExit = new javax.swing.JMenuItem();
        jMenu2 = new javax.swing.JMenu();
        miFind = new javax.swing.JMenuItem();
        jMenu4 = new javax.swing.JMenu();
        jMenuItem1 = new javax.swing.JMenuItem();
        jMenuItem2 = new javax.swing.JMenuItem();
        jMenuItem4 = new javax.swing.JMenuItem();
        jMenu3 = new javax.swing.JMenu();
        miAbout = new javax.swing.JMenuItem();
        jMenuItem5 = new javax.swing.JMenuItem();

        setDefaultCloseOperation(javax.swing.WindowConstants.DO_NOTHING_ON_CLOSE);
        setTitle("Encrypted Notes");
        setMinimumSize(new java.awt.Dimension(400, 300));
        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                formWindowClosing(evt);
            }
        });

        jPanel1.setBorder(javax.swing.BorderFactory.createEmptyBorder(2, 2, 2, 2));
        jPanel1.setLayout(new java.awt.BorderLayout());

        lbCaret.setText("00:00");
        jPanel1.add(lbCaret, java.awt.BorderLayout.WEST);

        jPanel2.setLayout(new java.awt.BorderLayout());

        tfFind.setForeground(java.awt.SystemColor.inactiveCaption);
        tfFind.setText("Find...");
        tfFind.setMinimumSize(new java.awt.Dimension(150, 19));
        tfFind.setPreferredSize(new java.awt.Dimension(150, 19));
        tfFind.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                tfFindFocusGained(evt);
            }
            public void focusLost(java.awt.event.FocusEvent evt) {
                tfFindFocusLost(evt);
            }
        });
        tfFind.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                tfFindKeyReleased(evt);
            }
        });
        jPanel2.add(tfFind, java.awt.BorderLayout.CENTER);

        btFind.setText("Find");
        btFind.setFocusable(false);
        btFind.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btFindActionPerformed(evt);
            }
        });
        jPanel2.add(btFind, java.awt.BorderLayout.EAST);

        jPanel1.add(jPanel2, java.awt.BorderLayout.EAST);

        getContentPane().add(jPanel1, java.awt.BorderLayout.SOUTH);

        tp.setFont(new java.awt.Font("Monospaced", 0, 12)); // NOI18N
        tp.addInputMethodListener(new java.awt.event.InputMethodListener() {
            public void inputMethodTextChanged(java.awt.event.InputMethodEvent evt) {
            }
            public void caretPositionChanged(java.awt.event.InputMethodEvent evt) {
                tpCaretPositionChanged(evt);
            }
        });
        tp.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyTyped(java.awt.event.KeyEvent evt) {
                tpKeyTyped(evt);
            }
            public void keyPressed(java.awt.event.KeyEvent evt) {
                tpKeyPressed(evt);
            }
        });
        jScrollPane1.setViewportView(tp);

        getContentPane().add(jScrollPane1, java.awt.BorderLayout.CENTER);

        jMenu1.setText("File");

        miNew.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_N, java.awt.event.InputEvent.CTRL_MASK));
        miNew.setText("New document...");
        miNew.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miNewActionPerformed(evt);
            }
        });
        jMenu1.add(miNew);

        miOpen.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_O, java.awt.event.InputEvent.CTRL_MASK));
        miOpen.setText("Open...");
        miOpen.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miOpenActionPerformed(evt);
            }
        });
        jMenu1.add(miOpen);

        miSave.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_S, java.awt.event.InputEvent.CTRL_MASK));
        miSave.setText("Save");
        miSave.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miSaveActionPerformed(evt);
            }
        });
        jMenu1.add(miSave);

        miSaveAs.setText("Save As...");
        miSaveAs.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miSaveAsActionPerformed(evt);
            }
        });
        jMenu1.add(miSaveAs);
        jMenu1.add(jSeparator1);

        miExit.setText("Exit");
        miExit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miExitActionPerformed(evt);
            }
        });
        jMenu1.add(miExit);

        jMenuBar1.add(jMenu1);

        jMenu2.setText("Edit");

        miFind.setAccelerator(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_F, java.awt.event.InputEvent.CTRL_MASK));
        miFind.setText("Find...");
        miFind.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miFindActionPerformed(evt);
            }
        });
        jMenu2.add(miFind);

        jMenuBar1.add(jMenu2);

        jMenu4.setText("Tool");

        jMenuItem1.setText("Connect Card");
        jMenuItem1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem1ActionPerformed(evt);
            }
        });
        jMenu4.add(jMenuItem1);

        jMenuItem2.setText("Disconnect Card");
        jMenuItem2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem2ActionPerformed(evt);
            }
        });
        jMenu4.add(jMenuItem2);

        jMenuItem4.setText("Reset Card");
        jMenuItem4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem4ActionPerformed(evt);
            }
        });
        jMenu4.add(jMenuItem4);

        jMenuBar1.add(jMenu4);

        jMenu3.setText("Help");

        miAbout.setText("About");
        miAbout.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miAboutActionPerformed(evt);
            }
        });
        jMenu3.add(miAbout);

        jMenuItem5.setText("Javacard");
        jMenuItem5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem5ActionPerformed(evt);
            }
        });
        jMenu3.add(jMenuItem5);

        jMenuBar1.add(jMenu3);

        setJMenuBar(jMenuBar1);

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void miExitActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miExitActionPerformed
        if (!canExit())
            return;
        this.setVisible(false);
        System.exit(0);
    }//GEN-LAST:event_miExitActionPerformed

    private void formWindowClosing(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_formWindowClosing
        if (!canExit())
            return;
        this.setVisible(false);
        System.exit(0);
    }//GEN-LAST:event_formWindowClosing

    private void miNewActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miNewActionPerformed
        if (checkSave(WHYSAVE_CLOSE) == OPT_CANCEL)
            return;
        tp.setText("");
        docm = new DocMetadata();
        updateTitle();
    }//GEN-LAST:event_miNewActionPerformed

    private void miSaveActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miSaveActionPerformed
        if (docm.filename == null) {
            miSaveAsActionPerformed(evt);
            return;
        }
        checkSave(WHYSAVE_SAVE);
    }//GEN-LAST:event_miSaveActionPerformed

    private void miSaveAsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miSaveAsActionPerformed
        checkSave(WHYSAVE_SAVEAS);
    }//GEN-LAST:event_miSaveAsActionPerformed

    private void tpKeyTyped(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_tpKeyTyped

    }//GEN-LAST:event_tpKeyTyped

    private void tpCaretPositionChanged(java.awt.event.InputMethodEvent evt) {//GEN-FIRST:event_tpCaretPositionChanged
        updateCaretStatus();
    }//GEN-LAST:event_tpCaretPositionChanged

    private void tpKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_tpKeyPressed
        if (!docm.modified) {
            docm.modified = true;
            updateTitle();
        }
    }//GEN-LAST:event_tpKeyPressed

    private void tfFindFocusGained(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_tfFindFocusGained
        if (tfFind.getText().equals("Find...")) {
            tfFind.setForeground(java.awt.SystemColor.controlText);
            tfFind.setText("");
        }
    }//GEN-LAST:event_tfFindFocusGained

    private void tfFindFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_tfFindFocusLost
        if (tfFind.getText().equals("")) {
            tfFind.setText("Find...");
            tfFind.setForeground(java.awt.SystemColor.inactiveCaption);
        }
        searcher.removeHighlights();
    }//GEN-LAST:event_tfFindFocusLost

    private void miOpenActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miOpenActionPerformed
        openFile();
    }//GEN-LAST:event_miOpenActionPerformed

    private void miFindActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miFindActionPerformed
        tfFind.requestFocus();
    }//GEN-LAST:event_miFindActionPerformed

    private void tfFindKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_tfFindKeyReleased
        if (evt.getKeyChar() == 10 ) {
            doSearch();
            evt.consume();
        }
    }//GEN-LAST:event_tfFindKeyReleased

    private void btFindActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btFindActionPerformed
        doSearch();
    }//GEN-LAST:event_btFindActionPerformed

    private void miAboutActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miAboutActionPerformed
        JOptionPane.showMessageDialog(this, "Encrypted Notepad "+Main.VERSION+"\n(c) 2010. Ivan Voras <ivoras@gmail.com>\n"+
                "Released under the BSD License\nProject web: http://sourceforge.net/projects/enotes\n\nUsing "+Doc.CRYPTO_MODE);
    }//GEN-LAST:event_miAboutActionPerformed

    private void jMenuItem1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem1ActionPerformed
        // TODO add your handling code here:
        ConnectCard();
    }//GEN-LAST:event_jMenuItem1ActionPerformed

    private void jMenuItem2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem2ActionPerformed
        // TODO add your handling code here:
        DisconnectCard();
    }//GEN-LAST:event_jMenuItem2ActionPerformed

    private void jMenuItem4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem4ActionPerformed
        // TODO add your handling code here:
        try {
            cardAPI.setPIN();
            JOptionPane.showMessageDialog(this, "The user pin is set successfully");
        }
        catch (EnotesException ex){
            JOptionPane.showMessageDialog(this, "The user PIN setup failed",
                    "PIN setup", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_jMenuItem4ActionPerformed

    private void jMenuItem5ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem5ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jMenuItem5ActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btFind;
    private javax.swing.JMenu jMenu1;
    private javax.swing.JMenu jMenu2;
    private javax.swing.JMenu jMenu3;
    private javax.swing.JMenu jMenu4;
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JMenuItem jMenuItem2;
    private javax.swing.JMenuItem jMenuItem4;
    private javax.swing.JMenuItem jMenuItem5;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JLabel lbCaret;
    private javax.swing.JMenuItem miAbout;
    private javax.swing.JMenuItem miExit;
    private javax.swing.JMenuItem miFind;
    private javax.swing.JMenuItem miNew;
    private javax.swing.JMenuItem miOpen;
    private javax.swing.JMenuItem miSave;
    private javax.swing.JMenuItem miSaveAs;
    private javax.swing.JTextField tfFind;
    private javax.swing.JTextPane tp;
    // End of variables declaration//GEN-END:variables
      
       private boolean canExit() {
        return checkSave(WHYSAVE_CLOSE) != OPT_CANCEL;
    }
    

    private void updateTitle() {
        String fn = docm.filename;
        if (fn == null)
            fn = "*New Document*";
        if (docm.modified)
            fn += " [modified]";
        this.setTitle(fn + " - Encrypted Notepad");
    }


    private void updateCaretStatus() {
        docm.caretPosition = tp.getCaretPosition();
        lbCaret.setText(String.format("L:%d C:%s", tp_line, tp_col));
    }


    /**
     * Returns true if the document was saved or the user said he doesn't want
     * to save it.
     *
     * @return
     */
    private int checkSave(int whySave) {
        if ((whySave == WHYSAVE_SAVE || whySave == WHYSAVE_CLOSE) && !docm.modified)
            return OPT_NOSAVE;

        if (whySave == WHYSAVE_CLOSE) {
            int opt = JOptionPane.showConfirmDialog(this, "Do you want to save the file "+(docm.filename != null ? docm.filename : ""), "Save file?",
                    JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
            if (opt == JOptionPane.CANCEL_OPTION)
                return OPT_CANCEL;
            if (opt == JOptionPane.NO_OPTION)
                return OPT_NOSAVE;
        }

        if (docm.key == null) {
            String pwd = PasswordDialog.getPassword(cardAPI);
            if (pwd == null)
                return OPT_CANCEL;
            docm.setKey(pwd);
        }

        File fSave = null;
        if (whySave == WHYSAVE_SAVEAS || docm.filename == null) {
            JFileChooser fch = new JFileChooser();
            fch.addChoosableFileFilter(new FileFilter() {
                @Override
                public boolean accept(File f) {
                    if (f.isDirectory())
                        return true;
                    String name = f.getName().toLowerCase();
                    return name.endsWith(".txt");
                }
                @Override
                public String getDescription() {
                    return "Plain text files (*.txt)";
                }
            });
            fch.addChoosableFileFilter(new FileFilter() {
                public boolean accept(File f) {
                    if (f.isDirectory())
                        return true;
                    String name = f.getName().toLowerCase();
                    return name.endsWith(".etxt");
                }
                @Override
                public String getDescription() {
                    return "Encrypted Notepad files (*.etxt)";
                }
            });
            int ret = fch.showSaveDialog(this);
            if (ret == JFileChooser.APPROVE_OPTION) {
                fSave = fch.getSelectedFile();
                if (fSave.getName().indexOf(".") == -1)
                    fSave = new File(fSave.getAbsolutePath() + ".etxt");
            } else
                return OPT_NOSAVE;
        } else
            fSave = new File(docm.filename);
        
        docm.filename = fSave.getAbsolutePath();
        try {
            Doc doc = new Doc(tp.getText(), docm);
            boolean saved = doc.doSave(fSave);
            if (saved) {
                docm.modified = false;
                updateTitle();
                return OPT_SAVE;
            }
            return OPT_CANCEL;
        } catch (FileNotFoundException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage());
            Logger.getLogger(MainForm.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            return OPT_CANCEL;
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage());
            Logger.getLogger(MainForm.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            return OPT_CANCEL;
        }
    }


    /**
     * Returns true if a file was loaded.
     * 
     * @return
     */
    private boolean openFile() {
        if (checkSave(WHYSAVE_CLOSE) == OPT_CANCEL)
            return false;

        JFileChooser fch = new JFileChooser();
        fch.addChoosableFileFilter(new FileFilter() {
            @Override
            public boolean accept(File f) {
                if (f.isDirectory())
                    return true;
                String name = f.getName().toLowerCase();
                return name.endsWith(".txt");
            }
            @Override
            public String getDescription() {
                return "Plain text files (*.txt)";
            }
        });
        fch.addChoosableFileFilter(new FileFilter() {
            public boolean accept(File f) {
                if (f.isDirectory())
                    return true;
                String name = f.getName().toLowerCase();
                return name.endsWith(".etxt");
            }
            @Override
            public String getDescription() {
                return "Encrypted Notepad files (*.etxt)";
            }
        });

        File fOpen = null;

        int ret = fch.showOpenDialog(this);
        if (ret == JFileChooser.APPROVE_OPTION)
            fOpen = fch.getSelectedFile();
        else
            return false;

        return internalOpenFile(fOpen);
    }


    /*
     * Open a file that's certainly there.
     */
    boolean internalOpenFile(File fOpen) {
        Doc doc = new Doc();
        while (true) {
            try {
                String pwd = PasswordDialog.getPassword(cardAPI);
                if (pwd == null)
                    return false;
                if (doc.doOpen(fOpen, pwd))
                    break;
                else
                    return false;
            } catch (DocPasswordException ex) {
                continue;
            } catch (DocException ex) {
                Logger.getLogger(MainForm.class.getName()).log(Level.SEVERE, null, ex);
                JOptionPane.showMessageDialog(this, ex.getMessage());
                return false;
            } catch (FileNotFoundException ex) {
                Logger.getLogger(MainForm.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
                JOptionPane.showMessageDialog(this, ex.getMessage());
                return false;
            } catch (IOException ex) {
                Logger.getLogger(MainForm.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
                JOptionPane.showMessageDialog(this, "IOException: "+ex.getMessage());
                return false;
            }
        }

        docm = doc.getDocMetadata();
        tp.setText(doc.getText());
        tp.setCaretPosition(docm.caretPosition);
        updateTitle();
        return true;
    }

    private boolean ConnectCard()
    {
        try 
        {
            if( this.pinDialog.UserAuth == 1)
            {
                System.out.println("User already connected!!");
                JOptionPane.showMessageDialog(this, "User already connected!!");
                return true;
            }
           
            cardAPI.ConnectCard();
            System.out.println("Card Connected");
            
            pinDialog.setCardAPI(cardAPI);
            pinDialog.setResizable(false);
            pinDialog.setModal(true);
            pinDialog.setLocationRelativeTo(null);
            pinDialog.setVisible(true);                    
            
            if(pinDialog.UserAuth == 0)
            {
                System.out.println("User not Authenticated!!");
                pinDialog.setVisible(false);
                return false ;
            }
            else if(pinDialog.Cancel == 1)
            {
                pinDialog.setVisible(false);
                return false ;                
            }
            
           
                       

            
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
        JOptionPane.showMessageDialog(this, "JavaCard connected");
        return true ;
    }
    
    public void DisconnectCard() 
    {
        try
        {
            cardAPI.DisconnectFromCard();
            this.pinDialog.Reintialize();
            JOptionPane.showMessageDialog(this, "Card is disConnected");
        }
        catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
      
    }
    
    /**
     * Highlight search words.
     */
    private void doSearch() {
        String findText = tfFind.getText();
        if (findText.length() != 0) {
            if (searcher.search(findText) == -1)
                JOptionPane.showMessageDialog(this, "Not found: "+findText);
        }
    }
}
