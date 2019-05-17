
/**
 * File: AESCipher.java
 * Author: Brandi Coon
 * Course: MSCS 630
 * Assignment: Lab 5
 * Due Date: March 17, 2019 (submitted late due to softball travelling and games)
 * Version: 1.0
 * 
 * This file contains the code to implement
 *  an AES Cipher.
 */

/**
 * AESCipher
 * 
 * This class contains a few methods, all of which
 *  help to perform the AES Cipher.
 * 
 */

public class AEScipher {
  
  // constant to hold the SBox MATRIX
  public static final String[][] sBox = {
      {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76"},
      {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0"},
      {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15"},
      {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},
      {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},
      {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},
      {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},
      {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},
      {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},
      {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},
      {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},
      {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},
      {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},
      {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},
      {"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},
      {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"}};
  
  // constant to hold the Rcon ARRAY  (0-15 rounds in first "row")
  public static final String[] rcon = { "8D", "01",  "02",  "04",  "08",  "10",  "20",  "40",  "80",  "1B",  "36",  "6C",  "D8",  "AB",  "4D",  "9A",
       "2F",  "5E",  "BC",  "63",  "C6",  "97",  "35",  "6A",  "D4",  "B3",  "7D",  "FA",  "EF",  "C5",  "91",  "39",
       "72",  "E4",  "D3",  "BD",  "61",  "C2",  "9F",  "25",  "4A",  "94",  "33",  "66",  "CC",  "83",  "1D",  "3A",
       "74",  "E8",  "CB",  "8D",  "01",  "02",  "04",  "08",  "10",  "20", "40",  "80",  "1B",  "36",  "6C",  "D8",
       "AB",  "4D",  "9A",  "2F",  "5E",  "BC", "63",  "C6",  "97",  "35",  "6A",  "D4",  "B3",  "7D",  "FA",  "EF",
       "C5",  "91",  "39",  "72",  "E4",  "D3",  "BD",  "61",  "C2",  "9F",  "25",  "4A",  "94",  "33",  "66",  "CC",
       "83",  "1D",  "3A",  "74",  "E8",  "CB",  "8D",  "01",  "02",  "04",  "08",  "10",  "20",  "40",  "80",  "1B",
       "36",  "6C",  "D8",  "AB",  "4D",  "9A",  "2F",  "5E",  "BC",  "63",  "C6",  "97",  "35",  "6A",  "D4",  "B3",
       "7D",  "FA",  "EF",  "C5",  "91",  "39",  "72",  "E4",  "D3",  "BD",  "61",  "C2",  "9F",  "25",  "4A",  "94",
       "33",  "66",  "CC",  "83",  "1D",  "3A",  "74",  "E8",  "CB",  "8D",  "01",  "02",  "04",  "08",  "10",  "20",
       "40",  "80",  "1B",  "36",  "6C",  "D8",  "AB",  "4D",  "9A",  "2F",  "5E",  "BC",  "63",  "C6",  "97",  "35",
       "6A",  "D4",  "B3",  "7D",  "FA",  "EF",  "C5",  "91",  "39",  "72",  "E4",  "D3",  "BD",  "61",  "C2",  "9F",
       "25",  "4A",  "94",  "33",  "66",  "CC",  "83",  "1D",  "3A",  "74",  "E8",  "CB",  "8D",  "01", "02",  "04",
       "08",  "10",  "20",  "40",  "80",  "1B",  "36",  "6C",  "D8",  "AB",  "4D",  "9A",  "2F",  "5E",  "BC",  "63",
       "C6",  "97",  "35",  "6A",  "D4",  "B3",  "7D",  "FA",  "EF",  "C5",  "91",  "39",  "72",  "E4",  "D3",  "BD",
       "61",  "C2",  "9F",  "25",  "4A",  "94",  "33",  "66",  "CC",  "83",  "1D",  "3A",  "74",  "E8",  "CB"};
  
  // Galois matrix
  public static final String[][] galois = {{"02", "03", "01", "01"},
      {"01", "02", "03", "01"},
      {"01", "01", "02", "03"},
      {"03", "01", "01", "02"}};
  
  /*
   * Look up tables used for MixColumns that were found on the Rijndael MixColumns Wikipedia Page.
   * Each table is used based on what a certain number is multiplied by (i.e. If some number 'a' is multiplied by 3, use the mc3 table.)
   */

  public static final String[][] mc2 ={{"00", "02", "04", "06", "08", "0A", "0C", "0E", "10", "12", "14", "16", "18", "1A", "1C", "1E"},
                                          {"20", "22", "24", "26", "28", "2A", "2C", "2E", "30", "32", "34", "36", "38", "3A", "3C", "3E"},
                                          {"40", "42", "44", "46", "48", "4A", "4C", "4E", "50", "52", "54", "56", "58", "5A", "5C", "5E"},
                                          {"60", "62", "64", "66", "68", "6A", "6C", "6E", "70", "72", "74", "76", "78", "7A", "7C", "7E"},
                                          {"80", "82", "84", "86", "88", "8A", "8C", "8E", "90", "92", "94", "96", "98", "9A", "9C", "9E"},
                                          {"A0", "A2", "A4", "A6", "A8", "AA", "AC", "AE", "B0", "B2", "B4", "B6", "B8", "BA", "BC", "BE"},
                                          {"C0", "C2", "C4", "C6", "C8", "CA", "CC", "CE", "D0", "D2", "D4", "D6", "D8", "DA", "DC", "DE"},
                                          {"E0", "E2", "E4", "E6", "E8", "EA", "EC", "EE", "F0", "F2", "F4", "F6", "F8", "FA", "FC", "FE"},
                                          {"1B", "19", "1F", "1D", "13", "11", "17", "15", "0B", "09", "0F", "0D", "03", "01", "07", "05"},
                                          {"3B", "39", "3F", "3D", "33", "31", "37", "35", "2B", "29", "2F", "2D", "23", "21", "27", "25"},
                                          {"5B", "59", "5F", "5D", "53", "51", "57", "55", "4B", "49", "4F", "4D", "43", "41", "47", "45"},
                                          {"7B", "79", "7F", "7D", "73", "71", "77", "75", "6B", "69", "6F", "6D", "63", "61", "67", "65"},
                                          {"9B", "99", "9F", "9D", "93", "91", "97", "95", "8B", "89", "8F", "8D", "83", "81", "87", "85"},
                                          {"BB", "B9", "BF", "BD", "B3", "B1", "B7", "B5", "AB", "A9", "AF", "AD", "A3", "A1", "A7", "A5"},
                                          {"DB", "D9", "DF", "DD", "D3", "D1", "D7", "D5", "CB", "C9", "CF", "CD", "C3", "C1", "C7", "C5"},
                                          {"FB", "F9", "FF", "FD", "F3", "F1", "F7", "F5", "EB", "E9", "EF", "ED", "E3", "E1", "E7", "E5"}};

  public static final String[][] mc3 ={   {"00","03","06","05","0C","0F","0A","09","18","1B","1E","1D","14","17","12","11"},
                                              {"30","33","36","35","3C","3F","3A","39","28","2B","2E","2D","24","27","22","21"},
                                              {"60","63","66","65","6C","6F","6A","69","78","7B","7E","7D","74","77","72","71"},
                                              {"50","53","56","55","5C","5F","5A","59","48","4B","4E","4D","44","47","42","41"},
                                              {"C0","C3","C6","C5","CC","CF","CA","C9","D8","DB","DE","DD","D4","D7","D2","D1"},
                                              {"F0","F3","F6","F5","FC","FF","FA","F9","E8","EB","EE","ED","E4","E7","E2","E1"},
                                              {"A0","A3","A6","A5","AC","AF","AA","A9","B8","BB","BE","BD","B4","B7","B2","B1"},
                                              {"90","93","96","95","9C","9F","9A","99","88","8B","8E","8D","84","87","82","81"},
                                              {"9B","98","9D","9E","97","94","91","92","83","80","85","86","8F","8C","89","8A"},
                                              {"AB","A8","AD","AE","A7","A4","A1","A2","B3","B0","B5","B6","BF","BC","B9","BA"},
                                              {"FB","F8","FD","FE","F7","F4","F1","F2","E3","E0","E5","E6","EF","EC","E9","EA"},
                                              {"CB","C8","CD","CE","C7","C4","C1","C2","D3","D0","D5","D6","DF","DC","D9","DA"},
                                              {"5B","58","5D","5E","57","54","51","52","43","40","45","46","4F","4C","49","4A"},
                                              {"6B","68","6D","6E","67","64","61","62","73","70","75","76","7F","7C","79","7A"},
                                              {"3B","38","3D","3E","37","34","31","32","23","20","25","26","2F","2C","29","2A"},
                                              {"0B","08","0D","0E","07","04","01","02","13","10","15","16","1F","1C","19","1A"}   };
  
  /**
   * aesRoundKeys
   *
   * This function produces 11 round keys for the AES Cipher
   * 
   * Parameters:
   *   String keyHex: a length 16-hex string representation of the system key Ke
   * 
   * Return value (roundKeysHex): an 11-row string array representation of all the round keys.
   *  Each element of roundKeysHex will contain a 16-hex string corresponding to each round key
   */
  public static String[] aesRoundKeys(String keyHex) {
    
    // The Ke matrix, W matrix, and solution matrix
    String[][] kMatrix = new String [4][4];
    String [][] wMatrix = new String [4][44];
    String[] roundKeysHex = {"", "", "", "", "", "", "", "", "", "", ""};
    
    // Variables to keep track of the current round and current
    // column index we are operating on
    double round = 0;
    int colIndex = 0;
    
    String [] keyHexArr = keyHex.split("(?<=\\G..)");
    //System.out.println(java.util.Arrays.toString(keyHexArr));
    
    // Add the keyHex input to the 4x4 Ke matrix
    int m = 0;
    for(int i = 0; i < 4; i++) {
      
      for(int j = 0; j < 4; j ++) {
        
        kMatrix[j][i] = keyHexArr[m];
        m++;
        
      }
      
    }
    
    // Put the key into the first four columns of the 4x44 W matrix
    for(int i = 0; i < 4; i++) {
      
      for(int j = 0; j < 4; j++) {
        
        wMatrix[i][j] = kMatrix[i][j];
        
      }
      
    }
    
    // We should now be at round 1 (round 0 was filling the key into
    // the first four columns), and we filled in columns 0-3 so we should
    // now be working on 4 and up
    round = 1;
    colIndex = 4;
    
    // Calculate the rest of the 40 columns in the W matrix
    while(round < 11.0 && colIndex < 44) {
      
      round = Math.floor(colIndex/4);
      
      // If it is a multiple of 4...
      // else if it is not a multiple of 4...
      if(colIndex % 4 == 0) {
        
        String[] wNew = new String[4];
        
        for(int i = 0; i < 4; i++) {
          wNew[i] = wMatrix[i][colIndex - 1]; 
        }
        
        // Shift the values left
        wNew = shiftLeft(wNew);
        
        // Use S-Box function to transform each of the four bytes
        for(int i = 0; i < 4; i++) {
          wNew[i] = aesSBox(wNew[i]);
        }
        
        // Get Rcon(i) constant for the ith round
        String rConConst = aesRcon((int)round);
        
        // XOR the columns
        String newEl = xorHex(rConConst,wNew[0]);
        
        wNew[0] = newEl;
        
        String [] jMin4Col = new String[4];
        // Retrieve the values from the two columns that will need the XOR operation
        for(int i = 0; i < 4; i++) {
          
          jMin4Col[i] = wMatrix[i][colIndex - 4];
          
        }
        
        String s1 = "";
        String s2 = "";
        
        for(int i = 0; i < 4; i ++) {
          
          s1 = s1 + jMin4Col[i];
          s2 = s2 + wNew[i];
          
        }
        
        // XOR the columns
        String newCol = xorHex(s1,s2);
        String [] newColArr = newCol.split("(?<=\\G..)");
        
        
        // Put the newly generated column into the 4x44 W matrix
        for(int i = 0; i < 4; i++) {
            
            wMatrix[i][colIndex] = newColArr[i];
            
        }
        
      } else {
        
        // Columns for the values to be XORed
        String [] jMin4Col = new String[4];
        String [] jMin1Col = new String[4];
        
        // Retrieve the values from the two columns that will need the XOR operation
        for(int i = 0; i < 4; i++) {
          
          jMin4Col[i] = wMatrix[i][colIndex - 4];
          jMin1Col[i] = wMatrix[i][colIndex - 1];
          
        }
        
        String s1 = "";
        String s2 = "";
        
        for(int i = 0; i < 4; i ++) {
          
          s1 = s1 + jMin4Col[i];
          s2 = s2 + jMin1Col[i];
          
        }
        
        // XOR the columns
        String newCol = xorHex(s1,s2);
        String [] newColArr = newCol.split("(?<=\\G..)");
        
        // Put the XORed values into the newly generated column of the 4x44 W matrix
        for(int i = 0; i < 4; i++) {
          
              wMatrix[i][colIndex] = newColArr[i];
            
        }
        
      }
      
      colIndex++;
      
    }
    
    
    // Add the wMatrix into an Array of size 11 (for 11 rounds)
    int k = 0;
    int l = 0;
    for(int i = 0; i < 11; i++) {
      for(int j = 0; j < 16; j++) {
        roundKeysHex[i] = roundKeysHex[i] + wMatrix[k][l];
        k++;
        if(k >= 4) {
          k = 0;
          l ++;
        } 
      }
    }
    
    return roundKeysHex;
    
  }
  
  /**
   * aesSBox
   *
   * This function reads the SBox given a hexadecimal number
   * 
   * Parameters:
   *   String inHex: the given hexadecimal value used to read a new
   *   hex value from the table
   * 
   * Return value(outHex): the hexadecimal value obtained from the SBox
   */
  public static String aesSBox(String inHex) {
    
    // Convert the hex string into a decimal number
    int intInHex = Integer.parseInt(inHex, 16);
    
    // For the row column use the division operator by 16
    // (because we're dealing with hex numbers), and for the
    // column number use modulo to find the remainder
    String outHex = sBox[intInHex / 16][intInHex % 16];
    
    return outHex;
    
  }
  
  /**
   * aesRcon
   *
   * This function gets each round's constant
   * 
   * Parameters:
   *   int round: the current round number
   * 
   * Return value(outHex): the value obtained from the Rcon table
   */
  public static String aesRcon(int round) {
    
    return rcon[round];
    
  }
  
  /**
   * AESStateXOR
   *
   * This is a method for "AES Add Key". The inputs and outputs
   *  of this method are both four by four matrices where every element
   *  is a pair of hex digits and will perform the “Add Round Key” operation
   *  (that is, the entries of the output matrix are simply the XOR of the
   *  corresponding input matrix entries).
   * 
   * Parameters:
   *   String sHex: the four by four input string hex matrix
   *   String keyHex: the four by four key matrix
   * 
   * Return value(outStateHex): the result of the XOR of the input matrices
   */
  public static String AESStateXOR(String sHex, String keyHex) {
    
    // XOR the two input matrices
    String outStateHex = xorHex(sHex, keyHex);
    
    return outStateHex;
  }
  
  /**
   * AESNibbleSub
   *
   * This method’s input and output are supposed four by four matrices of pairs of hex digits
   * (I have them in an array format of 16 values of hex digits for now until I convert it later).
   * The method will perform the “Substitution” operation (the entries of the output matrix
   * result from running the corresponding input matrix entries through the AES SBox)
   * 
   * Parameters:
   *   String inStateHex: a four by four matrix of pairs of Hex digits
   * 
   * Return value(outStateHex): an array with 16 values of hex digits (which is really the 4x4 matrix
   * just in a different format) that is the result of running the input array (the supposed 4x4 matrix)
   * through the AES SBox
   */
  public static String[] AESNibbleSub(String inStateHex) {
    
    // Split the given string into an array with two hex digits in each spot
    String [] arr = inStateHex.split("(?<=\\G..)");
    
    // Perform the SBox substitution on each element in the array
    for(int i = 0; i < arr.length; i++) {
      arr[i] = aesSBox(arr[i]);
    }
    
    return arr;
  }
  
  /**
   * AESShiftRow
   *
   * This function's inputs and output are 4 by 4 matrices of pairs of hex digits
   * and will perform the "Shift Row" operation of the AES to transform the input
   * state matrix into output state (the input is an array of 16 hex values)
   * 
   * Parameters:
   *   String inStateHex: the four by four input matrix to be shifted (array of 16 values)
   * 
   * Return value(outStateHex): the four by four matrix after being shifted
   */
  public static String[][] AESShiftRow(String[] inStateHex) {
    
    String[][] m = new String[4][4];
    
    // Make it into a matrix
    int k = 0;
    for(int i = 0; i < 4; i++) {
      for(int j = 0; j < 4; j++) {
        m[j][i] = inStateHex[k];
        k++;
      }
    }
    
    // Shift the rows (row 0 remains unchanged, row 1 shifted one to the left,
    // row 2 shifted two to the left, and row 3 shifted three to the left)
    String[] shifted = new String[4];
    
    // row 1
    // Shift it once
    shifted = shiftLeft(m[1]);
    
    // Put it back into the matrix
    for(int o = 0; o < 4; o++) {
      m[1][o] = shifted[o];
    }
    
    // row 2
    shifted = shiftLeft(m[2]);
    shifted = shiftLeft(shifted);
    
    for(int i = 0; i < 4; i++) {
      m[2][i] = shifted[i];
    }
    
    // row 3
    shifted = shiftLeft(m[3]);
    shifted = shiftLeft(shifted);
    shifted = shiftLeft(shifted);
    
    for(int o = 0; o < 4; o++) {
      m[3][o] = shifted[o];
    }
    
    return m;
  }
  
  /**
   * AESMixColumn
   *
   * This function's input and output are 4 by 4 matrices of pairs of hex digits and
   * will perform the Mix Column operation of AES to transform the input state into output
   * state. This function is  performed by mapping each element in the current matrix with the value
   * returned by its helper function.
   * 
   * Parameters:
   *   String inStateHex: four by four matrix to be operated on
   * 
   * Return value(outStateHex): four by four matrix after Mix Column operation
   */
  public static String[][] AESMixColumn(String[][] inStateHex) {
    
    String[][] tempArray = new String[4][4];
    
    // Copy the elements of the matrix over to the temp matrix
    for(int i = 0; i < 4; i++){
        System.arraycopy(inStateHex[i], 0, tempArray[i], 0, 4);
    }
    
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
          inStateHex[j][i] = mcHelper(tempArray, galois, i, j);
      }
    }
    
    return inStateHex;
  }

  /**
   * mcHelper
   *
   * Helper method of mixColumns to use the mix columns formula on each element
   * 
   * Parameters:
   *   String[][] arr: the current matrix being checked
   *   String g: the galois matrix
   *   int i: row position
   *   int j: column position
   * 
   * Return value: computed mix columns value
   */
  public static String mcHelper(String[][] arr, String[][] g, int i, int j){
      
    String mcsum = "00";
      for (int k = 0; k < 4; k++) {
          int a = Integer.parseInt(g[i][k], 16);
          int b = Integer.parseInt(arr[k][j], 16);
          mcsum = xorHex(mcsum,mcCalc(a, b, arr[k][j]));
      }
      return mcsum;
  }

  /**
   * mcCalc
   *
   * Helper method used in mcHelper
   * 
   * Parameters:
   *   int a: the galois matrix number
   *   int b: the inStateHex array number
   * 
   * Return value: depending on the galois field number, we output the appropriate values
   */
  public static String mcCalc(int a, int b, String bString){
      
    if (a == 1) {
          return bString;
      } else if (a == 2) {
          return mc2[b / 16][b % 16];
      } else if (a == 3) {
          return mc3[b / 16][b % 16];
      }
      return "00";
  }
  
  /**
   * AES
   *
   * This function will perform the AES encryption following the algorithm
   * shown in Figure 1 of the Lab 5 description (using the Add Key, Nibble Substitution,
   * Shift Rows, and Mix Columns operations).
   * 
   * Parameters:
   *   String pTextHex: the input hex string of plain-text to be encrypted
   *   String keyHex: the input hex key
   * 
   * Return value(cTextHex): the output cipher-text in hex
   */
  public static String AES(String pTextHex, String keyHex) {
    
    int round = 0;
    String outStateHex;
    String[] outHex;
    String[][] outMatrixHex;
    String newPTextHex;
    
    // Generate the round keys
    String[] roundKeysHex = aesRoundKeys(keyHex);
    
    // Perform the first Add Key operation (round should be 0 at start)
    outStateHex = AESStateXOR(pTextHex, roundKeysHex[round]);
    round++;
    
    // Loop through the nibble substitution, shift rows, mix columns,
    // and add key methods until we reach the last round (i.e. round 10
    // from rounds 0-10 (total 11 rounds))
    while(round < 10) {
      outHex = AESNibbleSub(outStateHex);
      outMatrixHex = AESShiftRow(outHex);
      outMatrixHex = AESMixColumn(outMatrixHex);
      
      // Make the array into string form for the next function
      StringBuilder sb1 = new StringBuilder();
      for(int i = 0; i < 4; i++) {
          for(int j = 0; j < 4; j++) {
            sb1.append(outMatrixHex[i][j]);
          }
      }
      newPTextHex = sb1.toString();
      
      outStateHex = AESStateXOR(newPTextHex, roundKeysHex[round]);
      round++;
      
    }
    
    // Last round (i.e. round 10)
    outHex = AESNibbleSub(outStateHex);
    outMatrixHex = AESShiftRow(outHex);
    
    // Make the array into string form for the next function
    StringBuilder sb2 = new StringBuilder();
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
          sb2.append(outMatrixHex[j][i]);
        }
    }
    newPTextHex = sb2.toString();
    
    outStateHex = AESStateXOR(newPTextHex, roundKeysHex[round]);
    
    return outStateHex;
  }
  
  
  /**
   * shiftLeft
   *
   * This function shifts an array's values
   * one spot to the left
   * 
   * Parameters:
   *   int[] shiftArray: the array whose values we will be shifting
   * 
   * Return value: the newly left-shifted array
   */
  public static String[] shiftLeft(String[] shiftArray) {
    
    // store the first value in the array
    String temp = shiftArray[0];
    
    // iterate through the array and assign the new
    // shifted values
    for (int i = 0; i < shiftArray.length - 1; i++) {
      
        shiftArray[i] = shiftArray[i + 1];
        
    }
    
    // put the first value in the last spot
    shiftArray[shiftArray.length - 1] = temp;
    
    return shiftArray;
    
  }
  
  /*
   * xorHex
   *
   * This function xors two hex values
   * 
   * Parameters:
   *   String a: first string in the xor computation
   *   String b: second string in the xor computation
   * 
   * Return value: the result of the xor computation
   */
  public static String xorHex(String a, String b) {
    
    char[] characters = new char[a.length()];
    
    for (int i = 0; i < characters.length; i++) {
      
        characters[i] = toHex(fromHex(a.charAt(i)) ^ fromHex(b.charAt(i)));
        
    }
    return new String(characters);
  }

  /*
   * fromHex
   *
   * This function converts FROM hex values
   * 
   * Parameters:
   *   char c: character to be converted
   * 
   * Return value: converted value FROM hex
   */
  public static int fromHex(char c) {
    
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    throw new IllegalArgumentException();
    
  }

  /*
   * toHex
   *
   * This function converts TO a hex value
   * 
   * Parameters:
   *   int nibble: index of the hex value
   * 
   * Return value: the TO hex value conversion
   */
  public static char toHex(int nibble) {
    
    if (nibble < 0 || nibble > 15) {
        throw new IllegalArgumentException();
    }
    
    return "0123456789ABCDEF".charAt(nibble);
  }
  
}
