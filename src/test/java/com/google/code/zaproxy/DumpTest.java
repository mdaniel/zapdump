package com.google.code.zaproxy;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

public class DumpTest {
    @Test(dataProvider = "urlPairs")
    public void testCanonicalUrl(String input, String expected) throws Exception {
        assertEquals(Dump.canonicalUrl(input), expected);

    }

    @DataProvider(name = "urlPairs")
    public Object[][] getUrlPairs() {
        // {input, expected}
        return new Object[][] {
            // pathological cases
            {"http://www.example.com",
             "http://www.example.com/"
            },
            {"http://www.example.com/do?a=1&b=2&c=3",
             "http://www.example.com/do?a=1&b=2&c=3"
            },
            {"http://www.example.com/do?c=1&b=2&a=3",
             "http://www.example.com/do?a=3&b=2&c=1"
            },
            {"http://www.example.com/do?&a=1",
             "http://www.example.com/do?a=1"
            },

            // sorting by argument values
            {"http://www.example.com/do?c=3&b=5&b=2&a=50",
             "http://www.example.com/do?a=50&b=2&b=5&c=3"
            },

            // using keep_blank_values
            {"http://www.example.com/do?b=&a=2",
             "http://www.example.com/do?a=2&b="
            },
            {"http://www.example.com/do?b=&c&a=2",
             "http://www.example.com/do?a=2&b=&c="
            },

            {"http://www.example.com/do?1750,4",
             "http://www.example.com/do?1750%2C4="
            },

            // spaces
            {"http://www.example.com/do?q=a space&a=1",
             "http://www.example.com/do?a=1&q=a+space"
            },
            {"http://www.example.com/do?q=a+space&a=1",
             "http://www.example.com/do?a=1&q=a+space"
            },
            {"http://www.example.com/do?q=a%20space&a=1",
             "http://www.example.com/do?a=1&q=a+space"
            },

            // normalize percent-encoding case (in paths)
            {"http://www.example.com/a%a3do",
             "http://www.example.com/a%A3do"
            },
            // normalize percent-encoding case (in query arguments)
            {"http://www.example.com/do?k=b%a3",
             "http://www.example.com/do?k=b%A3"
            },

            // non-ASCII percent-encoding in paths
            {"http://www.example.com/a do?a=1",
             "http://www.example.com/a%20do?a=1"
            },
            {"http://www.example.com/a %20do?a=1",
             "http://www.example.com/a%20%20do?a=1"
            },
            // u00a3 = British pound sign
            {"http://www.example.com/a do\u00a3.html?a=1",
             "http://www.example.com/a%20do%C2%A3.html?a=1"
            },
            // non-ASCII percent-encoding in query arguments
            {"http://www.example.com/do?price=\u00a3500&a=5&z=3",
             "http://www.example.com/do?a=5&price=%C2%A3500&z=3"
            },
            {"http://www.example.com/do?price=\u00a3500&a=5&z=3",
             "http://www.example.com/do?a=5&price=%C2%A3500&z=3"
            },
            {"http://www.example.com/do?price(\u00a3},=500&a=1",
             "http://www.example.com/do?a=1&price%28%C2%A3%7D%2C=500"
            },

            // # urls containing auth and ports
            {"http://user:pass@www.example.com:81/do?now=1",
             "http://user:pass@www.example.com:81/do?now=1"
            },
            {"http://user:pass@www.example.com/do?a=1#frag",
             "http://user:pass@www.example.com/do?a=1#frag"
            },
            {
            "https://www.google.com/xjs/_/js/k=xjs.s.en_US.Pk6WM5xCqOI.O/m=c,sb_mob,jp,rcs,ivf,jsa,mbsf,bct,elog,r,hsm,pcc,csi/am=cEYFAg/rt=j/d=1/sv=1/rs=AItRSTPrWBBy_Zt149JrvH_iQSWBlQ023Q",
            "https://www.google.com/xjs/_/js/k=xjs.s.en_US.Pk6WM5xCqOI.O/m=c,sb_mob,jp,rcs,ivf,jsa,mbsf,bct,elog,r,hsm,pcc,csi/am=cEYFAg/rt=j/d=1/sv=1/rs=AItRSTPrWBBy_Zt149JrvH_iQSWBlQ023Q"
            },
        };
    }

    @Test
    public void testBizarreUrlHash() throws Exception {
        final String expectedSig = "71f427022b5b99cbe5bca86ef6d7961566730818";
        Dump.SignatureParts sig = new Dump.SignatureParts();
        sig.setRequestMethod("GET");
        sig.setRequestUrl("https://www.google.com/xjs/_/js/k=xjs.s.en_US.Pk6WM5xCqOI.O/m=c,sb_mob,jp,rcs,ivf,jsa,mbsf,bct,elog,r,hsm,pcc,csi/am=cEYFAg/rt=j/d=1/sv=1/rs=AItRSTPrWBBy_Zt149JrvH_iQSWBlQ023Q");
        assertEquals(sig.toString(), expectedSig);
    }
}
