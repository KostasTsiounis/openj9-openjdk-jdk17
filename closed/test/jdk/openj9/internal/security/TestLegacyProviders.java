/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2026, 2026 All Rights Reserved
 * ===========================================================================
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * IBM designates this particular file as subject to the "Classpath" exception
 * as provided by IBM in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, see <http://www.gnu.org/licenses/>.
 *
 * ===========================================================================
 */

/*
 * @test
 * @summary Test Restricted Security Mode with Legacy Providers
 * @library /test/lib
 * @run junit TestConstraintsSuccess
 */
import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.security.Security;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.process.ProcessTools;

public class TestLegacyProviders {
    public static class LegacyProvider extends Provider {
        public LegacyProvider() {
            super("LegacyProvider", "1", "Test provider");
            put("Signature.Test", "example.class.MyClass");
            put("Signature.Test2", "example.class.MyClass2");
            put("Signature.Test3", "example.class.MyClass3");

            putIfAbsent("Signature.Test4", "example.class.MyClass4");

            replace("Signature.Test2", "example.class.MyClass2New");
            replace("Signature.Test2", "example.class.MyClass2New", "example.class.MyClass2");

            replace("Signature.Test3", "example.class.MyClass3New");
            replace("Signature.Test3", "example.class.MyClass3", "example.class.MyClass3New");

            merge("Signature.Test5", "example.class.MyClass5", (a,b) -> b);

        }
    }

    private static Provider legacyProvider;

    private static void useLegacyPaths() throws RuntimeException {
        // Check get operation.
        String response = (String) legacyProvider.get("Signature.Test");
        if ((response == null) || !"example.class.MyClass".equals(response)) {
            throw new RuntimeException("Incorrect response for get()");
        }

        response = (String) legacyProvider.get("Signature.Test2");
        if ((response == null) || !"example.class.MyClass2".equals(response)) {
            throw new RuntimeException("Incorrect response for get()");
        }

        response = (String) legacyProvider.get("Signature.Test3");
        if (response != null) {
            throw new RuntimeException("Incorrect response for get()");
        }

        response = (String) legacyProvider.get("Signature.Test4");
        if ((response == null) || !"example.class.MyClass4".equals(response)) {
            throw new RuntimeException("Incorrect response for get()");
        }

        response = (String) legacyProvider.get("Signature.Test5");
        if ((response == null) || !"example.class.MyClass5".equals(response)) {
            throw new RuntimeException("Incorrect response for get()");
        }

        

        String[] acceptedValues = {"example.class.MyClass",
                                   "example.class.MyClass2",
                                   "example.class.MyClass4",
                                   "example.class.MyClass5"};


        // Check entrySet operation.
        Set<Map.Entry<Object,Object>> es = legacyProvider.entrySet();
        System.out.println(es.toString());
        for (Map.Entry<Object,Object> entry : es) {
            String stringValue = (String) entry.getValue();
            boolean found = false;
            for (String acceptedValue : acceptedValues) {
                if (stringValue.equals(acceptedValue)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw new RuntimeException("Incorrect values returned from entrySet()");
            }
        }

        // Check values operation.
        Collection<Object> values = legacyProvider.values();
        System.out.println(values.toString());
        for (Object value : values) {
            String stringValue = (String) value;
            boolean found = false;
            for (String acceptedValue : acceptedValues) {
                if (stringValue.equals(acceptedValue)
            || "1".equals(stringValue)                                      // Version from constructor
            || "com.ibm.test.TestLegacy$LegacyProvider".equals(stringValue) // Classname from constructor
            || "LegacyProvider".equals(stringValue)                         // Provider name from constructor
            || "Test provider".equals(stringValue)                          // Info from constructor
        ) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw new RuntimeException("Incorrect values returned from values()");
            }
        }

        // Check elements operation.
        Enumeration<Object> elements = legacyProvider.elements();
        while (elements.hasMoreElements()) {
            String stringElement = (String) elements.nextElement();
            boolean found = false;
            for (String acceptedValue : acceptedValues) {
                if (stringElement.equals(acceptedValue)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw new RuntimeException("Incorrect values returned from elements()");
            }
        }


        // Check getProperty operation.
        response = (String) legacyProvider.getProperty("Signature.Test");
        if ((response == null) || !"example.class.MyClass".equals(response)) {
            throw new RuntimeException("Incorrect response for getProperty()");
        }

        response = (String) legacyProvider.getProperty("Signature.Test2");
        if ((response == null) || !"example.class.MyClass2".equals(response)) {
            throw new RuntimeException("Incorrect response for getProperty()");
        }

        response = (String) legacyProvider.getProperty("Signature.Test3");
        if (response != null) {
            throw new RuntimeException("Incorrect response for getProperty()");
        }

        response = (String) legacyProvider.getProperty("Signature.Test4");
        if ((response == null) || !"example.class.MyClass4".equals(response)) {
            throw new RuntimeException("Incorrect response for getProperty()");
        }

        response = (String) legacyProvider.getProperty("Signature.Test5");
        if ((response == null) || !"example.class.MyClass5".equals(response)) {
            throw new RuntimeException("Incorrect response for getProperty()");
        }


        // Check compute operation.
        response = (String) legacyProvider.compute("Signature.Test", (a, b) -> (b + "New"));
        if ((response == null) || !"example.class.MyClassNew".equals(response)) {
            throw new RuntimeException("Incorrect response for compute()");
        }

        response = (String) legacyProvider.compute("Signature.Test3", (a, b) -> (b + "New"));
        if (response != null) {
            throw new RuntimeException("Incorrect response for compute()");
        }

        // Check computeIfAbsent operation.
        legacyProvider.remove("Signature.Test");
        response = (String) legacyProvider.computeIfAbsent("Signature.Test", a -> "example.class.MyClass");
        if ((response == null) || !"example.class.MyClass".equals(response)) {
            throw new RuntimeException("Incorrect response for computeIfAbsent()");
        }

        response = (String) legacyProvider.computeIfAbsent("Signature.Test3", a -> "example.class.MyClass3");
        if (response != null) {
            throw new RuntimeException("Incorrect response for computeIfAbsent()");
        }

        // Check computeIfPresent operation.
        response = (String) legacyProvider.computeIfPresent("Signature.Test", (a, b) -> (b + "New"));
        if ((response == null) || !"example.class.MyClassNew".equals(response)) {
            throw new RuntimeException("Incorrect response for computeIfPresent()");
        }

        response = (String) legacyProvider.computeIfPresent("Signature.Test3", (a, b) -> (b + "New"));
        if (response != null) {
            throw new RuntimeException("Incorrect response for computeIfPresent()");
        }

        String[] acceptedKeys = {"Signature.Test",
                                 "Signature.Test2",
                                 "Signature.Test4",
                                 "Signature.Test5"};

        // Check keys operation.
        Enumeration<Object> keys = legacyProvider.keys();
        while (keys.hasMoreElements()) {
            String stringKey = (String) keys.nextElement();
            boolean found = false;
            for (String acceptedKey : acceptedKeys) {
                if (stringKey.equals(acceptedKey)
                    || "Provider.id version".equals(stringKey)      // Version from constructor
                    || "Provider.id className".equals(stringKey)    // Provider classname from constructor
                    || "Provider.id info".equals(stringKey)         // Info from constructor
                    || "Provider.id name".equals(stringKey)         // Provider name from constructor
                ) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw new RuntimeException("Incorrect values returned from keys()");
            }
        }
    }

    @Test
    public void runWithConstraints() throws RuntimeException {
        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJava(
                "-Dsemeru.customprofile=TestLegacy.Version",
                "-Djava.security.properties=" + System.getProperty("test.src") + "/legacy-java.security",
                "TestLegacyProviders"
        );
        outputAnalyzer.reportDiagnosticSummary();
        outputAnalyzer.shouldHaveExitValue(0);
    }

    public static void main(String[] args) throws RuntimeException {
        Security.getProviders();
        Security.addProvider(new LegacyProvider());
        legacyProvider = Security.getProvider("LegacyProvider");
	    useLegacyPaths();
    }
}
