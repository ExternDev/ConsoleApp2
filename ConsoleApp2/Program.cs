using com.itextpdf.text.pdf.security;
using iTextSharp.text.pdf.security;
using iTextSharp.text.pdf;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.X509;

class Program
{
    public static void Main(string[] args)
    {
        string fileName = "D:\\SSo\\ssoapi\\ConsoleApp2\\ConsoleApp2\\sample-contract.pdf";
        string signPdf = "D:\\SSo\\ssoapi\\ConsoleApp2\\ConsoleApp2\\sample-contract_signed.pdf";
        string pathOfPfx = "D:\\SSo\\ssoapi\\ConsoleApp2\\ConsoleApp2\\fred.pfx";
        string password = "apples";

        SignPdf(fileName, signPdf, pathOfPfx, password);
    }
    private static void SignPdf(string mainPdfFilePath, string pathToNewSignFile, string pathToCerts, string passCert)
    {
        if (!File.Exists(pathToCerts))
        {
            Console.WriteLine("Certificate not exist " + pathToCerts);
            return;
        }

        var pass = passCert.ToCharArray();

        FileStream fs;
        try
        {
            fs = new FileStream(pathToCerts, FileMode.Open);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Could not open cert" + pathToCerts);
            return;
        }

        var store = new Pkcs12Store(fs, pass);

        fs.Close();

        var alias = "";

        // searching for private key
        foreach (string al in store.Aliases)
            if (store.IsKeyEntry(al) && store.GetKey(al).Key.IsPrivate)
            {
                alias = al;
                break;
            }

        var pk = store.GetKey(alias);

        ICollection<X509Certificate> chain = store.GetCertificateChain(alias).Select(c => c.Certificate).ToList();

        var parameters = pk.Key as RsaPrivateCrtKeyParameters;

        if (!File.Exists(mainPdfFilePath))
        {
            Console.WriteLine("Could not open file" + mainPdfFilePath + "  File not exist");
            return;
        }

        var reader = new PdfReader(mainPdfFilePath);
        
        //create a new PDF file 
        FileStream fileStreamSigPdf;
        try
        {
            fileStreamSigPdf = new FileStream(pathToNewSignFile, FileMode.Create);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Could not create file" + pathToNewSignFile);
            return;
        }

        var stamper = PdfStamper.CreateSignature(reader, fileStreamSigPdf, '\0', null, true);

        var appearance = stamper.SignatureAppearance;
        appearance.Reason = "my reason";
        appearance.Location = "India";
        appearance.SetVisibleSignature(new iTextSharp.text.Rectangle(100, 100, 250, 150), 1, null);

        IExternalSignature pks = new PrivateKeySignature(parameters, DigestAlgorithms.SHA256);
        MakeSignature.SignDetached(appearance, pks, chain, null, null, null, 0, CryptoStandard.CMS);

        fileStreamSigPdf.Close();
        reader.Close();
        stamper.Close();

        Console.WriteLine("Signed successfully " + mainPdfFilePath);
    }
}
