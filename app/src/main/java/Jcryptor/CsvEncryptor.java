package Jcryptor;

import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.io.input.BOMInputStream;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.FileInputStream;
import java.io.FileWriter;
//import java.io.*;
import java.nio.charset.Charset;

public class CsvEncryptor {
    private Encryptor encryptor;

    CsvEncryptor() {}
    CsvEncryptor(Encryptor encryptor) {
        setEncryptor(encryptor);
    }
    CsvEncryptor setEncryptor(Encryptor encryptor) {
        this.encryptor = encryptor;
        return this;
    }
    void doProc(String srcFileName, String outFileName) throws Exception {
        InputStream inputStream = new BOMInputStream(new FileInputStream(new File(srcFileName)));
        CSVParser parser = CSVParser.parse(inputStream, Charset.forName("UTF-8"), CSVFormat.RFC4180);

        CSVPrinter csvPrinter = new CSVPrinter(outFileName != null ? new FileWriter(outFileName) : new OutputStreamWriter(System.out), CSVFormat.RFC4180);
        
        for (CSVRecord record : parser) {
            for (String val : record) {
                if(encryptor != null) {
                    try {
                        val = encryptor.doProc(val);
                    } catch (Exception e) {
                    }
                }
                csvPrinter.print(val);
            }
            csvPrinter.println();
            csvPrinter.flush();
        }
    }
}
