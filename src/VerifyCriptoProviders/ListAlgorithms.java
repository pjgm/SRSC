package VerifyCriptoProviders; /**
 * Materiais/Labs para SRSC 16/17, Sem-2
 * Henrique Domingos, 12/3/17
 **/

import java.security.Provider;
import java.security.Security;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class ListAlgorithms
{
    /** 
     * Imprime set de entries - indentando um por linha, com o nome do set
     * nao indentado na primeira linha
     * 
     * @param setName : nome do set a imprimir
     * @param algorithms : set de algoritmos associado ao nome dado
     */
    public static void printSet(
        String setName,
        Set<String> algorithms)
    {
        System.out.println(setName + ":");
        
        if (algorithms.isEmpty())
        {
            System.out.println("            None available.");
        }
        else
        {
            Iterator	it = algorithms.iterator();
            
            while (it.hasNext())
            {
                String	name = (String)it.next();
                
                System.out.println("            " + name);
            }
        }
    }
    
    /**
     * List the available algorithm names for ciphers, key agreement, macs,
     * message digests and signatures.
     */
    public static void main(
        String[]    args)
    {
        Provider[] providers = Security.getProviders();
        Set        ciphers = new HashSet();
        Set        keyAgreements = new HashSet();
        Set        macs = new HashSet();
        Set        messageDigests = new HashSet();
        Set       signatures = new HashSet();
        
        for (int i = 0; i != providers.length; i++)
        {
            Iterator  it = providers[i].keySet().iterator();
            while (it.hasNext())
            {
                String	entry = (String)it.next();
                
                if (entry.startsWith("Alg.Alias."))
                {
                    entry = entry.substring("Alg.Alias.".length());
                }
                
                if (entry.startsWith("Cipher."))
                {
                    ciphers.add(entry.substring("Cipher.".length()));
                }
                else if (entry.startsWith("KeyAgreement."))
                {
                    keyAgreements.add(entry.substring("KeyAgreement.".length()));
                }
                else if (entry.startsWith("Mac."))
                {
                    macs.add(entry.substring("Mac.".length()));
                }
                else if (entry.startsWith("MessageDigest."))
                {
                    messageDigests.add(entry.substring("MessageDigest.".length()));
                }
                else if (entry.startsWith("Signature."))
                {
                    signatures.add(entry.substring("Signature.".length()));
                }
            }
        }
        
        printSet("Ciphers (Alg.): ", ciphers);
        printSet("KeyAgreeents: ", keyAgreements);
        printSet("MACs: ", macs);
        printSet("MessageDigests (Secure Hash-Functions): ", messageDigests);
        printSet("Signatures (Digital Sigantures w/ PubKey Methods) :", signatures);
    }
}


