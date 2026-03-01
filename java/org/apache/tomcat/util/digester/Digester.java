/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.digester;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.EmptyStackException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.IntrospectionUtils;
import org.apache.tomcat.util.IntrospectionUtils.PropertySource;
import org.apache.tomcat.util.buf.B2CConverter;
import org.apache.tomcat.util.res.StringManager;
import org.xml.sax.Attributes;
import org.xml.sax.EntityResolver;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.Locator;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import org.xml.sax.SAXParseException;
import org.xml.sax.XMLReader;
import org.xml.sax.ext.DefaultHandler2;
import org.xml.sax.ext.EntityResolver2;
import org.xml.sax.ext.Locator2;
import org.xml.sax.helpers.AttributesImpl;


/**
 * <p>A <strong>Digester</strong> processes an XML input stream by matching a
 * series of element nesting patterns to execute Rules that have been added
 * prior to the start of parsing.  This package was inspired by the
 * <code>XmlMapper</code> class that was part of Tomcat 3.0 and 3.1,
 * but is organized somewhat differently.</p>
 *
 * <p>See the <a href="package-summary.html#package_description">Digester
 * Developer Guide</a> for more information.</p>
 *
 * <p><strong>IMPLEMENTATION NOTE</strong> - A single Digester instance may
 * only be used within the context of a single thread at a time, and a call
 * to <code>parse()</code> must be completed before another can be initiated
 * even from the same thread.</p>
 *
 * <p><strong>IMPLEMENTATION NOTE</strong> - A bug in Xerces 2.0.2 prevents
 * the support of XML schema. You need Xerces 2.1/2.3 and up to make
 * this class working with XML schema</p>
 */
public class Digester extends DefaultHandler2 {

    // ---------------------------------------------------------- Static Fields

    protected static IntrospectionUtils.PropertySource[] propertySources;
    private static boolean propertySourcesSet = false;
    protected static final StringManager sm = StringManager.getManager(Digester.class);

    static {
        String classNames = System.getProperty("org.apache.tomcat.util.digester.PROPERTY_SOURCE");
        ArrayList<IntrospectionUtils.PropertySource> sourcesList = new ArrayList<>();
        IntrospectionUtils.PropertySource[] sources = null;
        if (classNames != null) {
            StringTokenizer classNamesTokenizer = new StringTokenizer(classNames, ",");
            while (classNamesTokenizer.hasMoreTokens()) {
                String className = classNamesTokenizer.nextToken().trim();
                ClassLoader[] cls = new ClassLoader[] { Digester.class.getClassLoader(),
                        Thread.currentThread().getContextClassLoader() };
                for (ClassLoader cl : cls) {
                    try {
                        Class<?> clazz = Class.forName(className, true, cl);
                        sourcesList.add((PropertySource) clazz.getConstructor().newInstance());
                        break;
                    } catch (Throwable t) {
                        ExceptionUtils.handleThrowable(t);
                        LogFactory.getLog(Digester.class).error(sm.getString("digester.propertySourceLoadError", className), t);
                    }
                }
            }
            sources = sourcesList.toArray(new IntrospectionUtils.PropertySource[0]);
        }
        if (sources != null) {
            propertySources = sources;
            propertySourcesSet = true;
        }
        if (Boolean.getBoolean("org.apache.tomcat.util.digester.REPLACE_SYSTEM_PROPERTIES")) {
            replaceSystemProperties();
        }
    }

    public static void setPropertySource(IntrospectionUtils.PropertySource propertySource) {
        if (!propertySourcesSet) {
            propertySources = new IntrospectionUtils.PropertySource[1];
            propertySources[0] = propertySource;
            propertySourcesSet = true;
        }
    }

    public static void setPropertySource(IntrospectionUtils.PropertySource[] propertySources) {
        if (!propertySourcesSet) {
            Digester.propertySources = propertySources;
            propertySourcesSet = true;
        }
    }

    private static final HashSet<String> generatedClasses = new HashSet<>();

    public static void addGeneratedClass(String className) {
        generatedClasses.add(className);
    }

    public static String[] getGeneratedClasses() {
        return generatedClasses.toArray(new String[0]);
    }

    public interface GeneratedCodeLoader {
        Object loadGeneratedCode(String className);
    }

    private static GeneratedCodeLoader generatedCodeLoader;

    public static boolean isGeneratedCodeLoaderSet() {
        return (Digester.generatedCodeLoader != null);
    }

    public static void setGeneratedCodeLoader(GeneratedCodeLoader generatedCodeLoader) {
        if (Digester.generatedCodeLoader == null) {
            Digester.generatedCodeLoader = generatedCodeLoader;
        }
    }

    public static Object loadGeneratedClass(String className) {
        if (generatedCodeLoader != null) {
            return generatedCodeLoader.loadGeneratedCode(className);
        }
        return null;
    }

    // --------------------------------------------------- Instance Variables


    /**
     * A {@link org.apache.tomcat.util.IntrospectionUtils.SecurePropertySource}
     * that uses environment variables to resolve expressions. Still available
     * for backwards compatibility.
     *
     * @deprecated Use {@link org.apache.tomcat.util.digester.EnvironmentPropertySource}
     *             This will be removed in Tomcat 10 onwards.
     */
    @Deprecated
    public static class EnvironmentPropertySource extends org.apache.tomcat.util.digester.EnvironmentPropertySource {
    }


    protected IntrospectionUtils.PropertySource[] source;


    /**
     * The body text of the current element.
     */
    protected StringBuilder bodyText = new StringBuilder();


    /**
     * The stack of body text string buffers for surrounding elements.
     */
    protected ArrayStack<StringBuilder> bodyTexts = new ArrayStack<>();


    /**
     * Stack whose elements are List objects, each containing a list of
     * Rule objects as returned from Rules.getMatch(). As each xml element
     * in the input is entered, the matching rules are pushed onto this
     * stack. After the end tag is reached, the matches are popped again.
     * The depth of is stack is therefore exactly the same as the current
     * "nesting" level of the input xml.
     *
     * @since 1.6
     */
    protected ArrayStack<List<Rule>> matches = new ArrayStack<>(10);

    /**
     * The class loader to use for instantiating application objects.
     * If not specified, the context class loader, or the class loader
     * used to load Digester itself, is used, based on the value of the
     * <code>useContextClassLoader</code> variable.
     */
    protected ClassLoader classLoader = null;


    /**
     * Has this Digester been configured yet.
     */
    protected boolean configured = false;


    /**
     * The EntityResolver used by the SAX parser. By default it use this class
     */
    protected EntityResolver entityResolver;

    /**
     * The URLs of entityValidator that have been registered, keyed by the public
     * identifier that corresponds.
     */
    protected HashMap<String, String> entityValidator = new HashMap<>();


    /**
     * The application-supplied error handler that is notified when parsing
     * warnings, errors, or fatal errors occur.
     */
    protected ErrorHandler errorHandler = null;


    /**
     * The SAXParserFactory that is created the first time we need it.
     */
    protected SAXParserFactory factory = null;

    /**
     * The Locator associated with our parser.
     */
    protected Locator locator = null;


    /**
     * The current match pattern for nested element processing.
     */
    protected String match = "";


    /**
     * Do we want a "namespace aware" parser.
     */
    protected boolean namespaceAware = false;


    /**
     * Registered namespaces we are currently processing.  The key is the
     * namespace prefix that was declared in the document.  The value is an
     * ArrayStack of the namespace URIs this prefix has been mapped to --
     * the top Stack element is the most current one.  (This architecture
     * is required because documents can declare nested uses of the same
     * prefix for different Namespace URIs).
     */
    protected HashMap<String, ArrayStack<String>> namespaces = new HashMap<>();


    /**
     * The parameters stack being utilized by CallMethodRule and
     * CallParamRule rules.
     */
    protected ArrayStack<Object> params = new ArrayStack<>();


    /**
     * The SAXParser we will use to parse the input stream.
     */
    protected SAXParser parser = null;


    /**
     * The public identifier of the DTD we are currently parsing under
     * (if any).
     */
    protected String publicId = null;


    /**
     * The XMLReader used to parse digester rules.
     */
    protected XMLReader reader = null;


    /**
     * The "root" element of the stack (in other words, the last object
     * that was popped.
     */
    protected Object root = null;


    /**
     * The <code>Rules</code> implementation containing our collection of
     * <code>Rule</code> instances and associated matching policy.  If not
     * established before the first rule is added, a default implementation
     * will be provided.
     */
    protected Rules rules = null;

    /**
     * The object stack being constructed.
     */
    protected ArrayStack<Object> stack = new ArrayStack<>();


    /**
     * Do we want to use the Context ClassLoader when loading classes
     * for instantiating new objects.  Default is <code>false</code>.
     */
    protected boolean useContextClassLoader = false;


    /**
     * Do we want to use a validating parser.
     */
    protected boolean validating = false;


    /**
     * Warn on missing attributes and elements.
     */
    protected boolean rulesValidation = false;


    /**
     * Fake attributes map (attributes are often used for object creation).
     */
    protected Map<Class<?>, List<String>> fakeAttributes = null;


    /**
     * The Log to which most logging calls will be made.
     */
    protected Log log = LogFactory.getLog(Digester.class);

    /**
     * The Log to which all SAX event related logging calls will be made.
     */
    protected Log saxLog = LogFactory.getLog("org.apache.tomcat.util.digester.Digester.sax");

    /**
     * Generated code.
     */
    protected StringBuilder code = null;

    public Digester() {
        propertySourcesSet = true;
        ArrayList<IntrospectionUtils.PropertySource> sourcesList = new ArrayList<>();
        boolean systemPropertySourceFound = false;
        if (propertySources != null) {
            for (IntrospectionUtils.PropertySource source : propertySources) {
                if (source instanceof SystemPropertySource) {
                    systemPropertySourceFound = true;
                }
                sourcesList.add(source);
            }
        }
        if (!systemPropertySourceFound) {
            sourcesList.add(new SystemPropertySource());
        }
        source = sourcesList.toArray(new IntrospectionUtils.PropertySource[0]);
    }


    public static void replaceSystemProperties() {
        Log log = LogFactory.getLog(Digester.class);
        if (propertySources != null) {
            Properties properties = System.getProperties();
            Set<String> names = properties.stringPropertyNames();
            for (String name : names) {
                String value = System.getProperty(name);
                if (value != null) {
                    try {
                        String newValue = IntrospectionUtils.replaceProperties(value, null, propertySources, null);
                        if (!value.equals(newValue)) {
                            System.setProperty(name, newValue);
                        }
                    } catch (Exception e) {
                        log.warn(sm.getString("digester.failedToUpdateSystemProperty", name, value), e);
                    }
                }
            }
        }
    }


    public void startGeneratingCode() {
        code = new StringBuilder();
    }

    public void endGeneratingCode() {
        code = null;
        known.clear();
    }

    public StringBuilder getGeneratedCode() {
        return code;
    }

    protected ArrayList<Object> known = new ArrayList<>();
    public void setKnown(Object object) {
        known.add(object);
    }
    public String toVariableName(Object object) {
        boolean found = false;
        int pos = 0;
        if (known.size() > 0) {
            for (int i = known.size() - 1; i >= 0; i--) {
                if (known.get(i) == object) {
                    pos = i;
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            pos = known.size();
            known.add(object);
        }
        return "tc_" + object.getClass().getSimpleName() + "_" + String.valueOf(pos);
    }

    // ------------------------------------------------------------- Properties

    /**
     * Return the currently mapped namespace URI for the specified prefix,
     * if any; otherwise return <code>null</code>.  These mappings come and
     * go dynamically as the document is parsed.
     *
     * @param prefix Prefix to look up
     * @return the namespace URI
     */
    public String findNamespaceURI(String prefix) {
        ArrayStack<String> stack = namespaces.get(prefix);
        if (stack == null) {
            return null;
        }
        try {
            return stack.peek();
        } catch (EmptyStackException e) {
            return null;
        }
    }


    /**
     * Return the class loader to be used for instantiating application objects
     * when required.  This is determined based upon the following rules:
     * <ul>
     * <li>The class loader set by <code>setClassLoader()</code>, if any</li>
     * <li>The thread context class loader, if it exists and the
     *     <code>useContextClassLoader</code> property is set to true</li>
     * <li>The class loader used to load the Digester class itself.
     * </ul>
     * @return the classloader
     */
    public ClassLoader getClassLoader() {
        if (this.classLoader != null) {
            return this.classLoader;
        }
        if (this.useContextClassLoader) {
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            if (classLoader != null) {
                return classLoader;
            }
        }
        return this.getClass().getClassLoader();
    }


    /**
     * Set the class loader to be used for instantiating application objects
     * when required.
     *
     * @param classLoader The new class loader to use, or <code>null</code>
     *  to revert to the standard rules
     */
    public void setClassLoader(ClassLoader classLoader) {
        this.classLoader = classLoader;
    }


    /**
     * @return the current depth of the element stack.
     */
    public int getCount() {
        return stack.size();
    }


    /**
     * @return the name of the XML element that is currently being processed.
     */
    public String getCurrentElementName() {
        String elementName = match;
        int lastSlash = elementName.lastIndexOf('/');
        if (lastSlash >= 0) {
            elementName = elementName.substring(lastSlash + 1);
        }
        return elementName;
    }


    /**
     * @return the error handler for this Digester.
     */
    public ErrorHandler getErrorHandler() {
        return this.errorHandler;
    }


    /**
     * Set the error handler for this Digester.
     *
     * @param errorHandler The new error handler
     */
    public void setErrorHandler(ErrorHandler errorHandler) {
        this.errorHandler = errorHandler;
    }


    /**
     * SAX parser factory method.
     * @return the SAXParserFactory we will use, creating one if necessary.
     * @throws ParserConfigurationException Error creating parser
     * @throws SAXNotSupportedException Error creating parser
     * @throws SAXNotRecognizedException Error creating parser
     */
    public SAXParserFactory getFactory() throws SAXNotRecognizedException, SAXNotSupportedException,
            ParserConfigurationException {

        if (factory == null) {
            factory = SAXParserFactory.newInstance();

            factory.setNamespaceAware(namespaceAware);
            // Preserve xmlns attributes
            if (namespaceAware) {
                factory.setFeature("http://xml.org/sax/features/namespace-prefixes", true);
            }

            factory.setValidating(validating);
            if (validating) {
                // Enable DTD validation
                factory.setFeature("http://xml.org/sax/features/validation", true);
                // Enable schema validation
                factory.setFeature("http://apache.org/xml/features/validation/schema", true);
            }

            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setXIncludeAware(false);
        }
        return factory;
    }


    /**
     * Sets a flag indicating whether the requested feature is supported
     * by the underlying implementation of <code>org.xml.sax.XMLReader</code>.
     * See <a href="http://www.saxproject.org/apidoc/xml/sax/package-summary.html#package-description">
     * http://www.saxproject.org/apidoc/xml/sax/package-summary.html#package-description</a>
     * for information about the standard SAX2 feature flags.  In order to be
     * effective, this method must be called <strong>before</strong> the
     * <code>getParser()</code> method is called for the first time, either
     * directly or indirectly.
     *
     * @param feature Name of the feature to set the status for
     * @param value The new value for this feature
     *
     * @exception ParserConfigurationException if a parser configuration error
     *  occurs
     * @exception SAXNotRecognizedException if the property name is
     *  not recognized
     * @exception SAXNotSupportedException if the property name is
     *  recognized but not supported
     */
    public void setFeature(String feature, boolean value) throws ParserConfigurationException,
            SAXNotRecognizedException, SAXNotSupportedException {

        getFactory().setFeature(feature, value);

    }


    /**
     * @return the current Logger associated with this instance of the Digester
     */
    public Log getLogger() {

        return log;

    }


    /**
     * Set the current logger for this Digester.
     * @param log The logger that will be used
     */
    public void setLogger(Log log) {

        this.log = log;

    }

    /**
     * Gets the logger used for logging SAX-related information.
     * <strong>Note</strong> the output is finely grained.
     *
     * @since 1.6
     * @return the SAX logger
     */
    public Log getSAXLogger() {

        return saxLog;
    }


    /**
     * Sets the logger used for logging SAX-related information.
     * <strong>Note</strong> the output is finely grained.
     * @param saxLog Log, not null
     *
     * @since 1.6
     */
    public void setSAXLogger(Log saxLog) {

        this.saxLog = saxLog;
    }

    /**
     * @return the current rule match path
     */
    public String getMatch() {

        return match;

    }


    /**
     * @return the "namespace aware" flag for parsers we create.
     */
    public boolean getNamespaceAware() {
        return this.namespaceAware;
    }


    /**
     * Set the "namespace aware" flag for parsers we create.
     *
     * @param namespaceAware The new "namespace aware" flag
     */
    public void setNamespaceAware(boolean namespaceAware) {
        this.namespaceAware = namespaceAware;
    }


    /**
     * Set the public id of the current file being parse.
     * @param publicId the DTD/Schema public's id.
     */
    public void setPublicId(String publicId) {
        this.publicId = publicId;
    }


    /**
     * @return the public identifier of the DTD we are currently
     * parsing under, if any.
     */
    public String getPublicId() {
        return this.publicId;
    }


    /**
     * @return the SAXParser we will use to parse the input stream.  If there
     * is a problem creating the parser, return <code>null</code>.
     */
    public SAXParser getParser() {

        // Return the parser we already created (if any)
        if (parser != null) {
            return parser;
        }

        // Create a new parser
        try {
            parser = getFactory().newSAXParser();
        } catch (Exception e) {
            log.error(sm.getString("digester.createParserError"), e);
            return null;
        }

        return parser;
    }


    /**
     * Return the current value of the specified property for the underlying
     * <code>XMLReader</code> implementation.
     * See <a href="http://www.saxproject.org/apidoc/xml/sax/package-summary.html#package-description">
     * http://www.saxproject.org/apidoc/xml/sax/package-summary.html#package-description</a>
     * for information about the standard SAX2 properties.
     *
     * @param property Property name to be retrieved
     * @return the property value
     * @exception SAXNotRecognizedException if the property name is
     *  not recognized
     * @exception SAXNotSupportedException if the property name is
     *  recognized but not supported
     */
    public Object getProperty(String property)
            throws SAXNotRecognizedException, SAXNotSupportedException {

        return getParser().getProperty(property);
    }


    /**
     * Return the <code>Rules</code> implementation object containing our
     * rules collection and associated matching policy.  If none has been
     * established, a default implementation will be created and returned.
     * @return the rules
     */
    public Rules getRules() {
        if (this.rules == null) {
            this.rules = new RulesBase();
            this.rules.setDigester(this);
        }
        return this.rules;
    }


    /**
     * Set the <code>Rules</code> implementation object containing our
     * rules collection and associated matching policy.
     *
     * @param rules New Rules implementation
     */
    public void setRules(Rules rules) {
        this.rules = rules;
        this.rules.setDigester(this);
    }


    /**
     * @return the boolean as to whether the context classloader should be used.
     */
    public boolean getUseContextClassLoader() {
        return useContextClassLoader;
    }


    /**
     * Determine whether to use the Context ClassLoader (the one found by
     * calling <code>Thread.currentThread().getContextClassLoader()</code>)
     * to resolve/load classes that are defined in various rules.  If not
     * using Context ClassLoader, then the class-loading defaults to
     * using the calling-class' ClassLoader.
     *
     * @param use determines whether to use Context ClassLoader.
     */
    public void setUseContextClassLoader(boolean use) {

        useContextClassLoader = use;

    }


    /**
     * @return the validating parser flag.
     */
    public boolean getValidating() {
        return this.validating;
    }


    /**
     * Set the validating parser flag.  This must be called before
     * <code>parse()</code> is called the first time.
     *
     * @param validating The new validating parser flag.
     */
    public void setValidating(boolean validating) {
        this.validating = validating;
    }


    /**
     * @return the rules validation flag.
     */
    public boolean getRulesValidation() {
        return this.rulesValidation;
    }


    /**
     * Set the rules validation flag.  This must be called before
     * <code>parse()</code> is called the first time.
     *
     * @param rulesValidation The new rules validation flag.
     */
    public void setRulesValidation(boolean rulesValidation) {
        this.rulesValidation = rulesValidation;
    }


    /**
     * @return the fake attributes list.
     */
    public Map<Class<?>, List<String>> getFakeAttributes() {
        return this.fakeAttributes;
    }


    /**
     * Determine if an attribute is a fake attribute.
     * @param object The object
     * @param name The attribute name
     * @return <code>true</code> if this is a fake attribute
     */
    public boolean isFakeAttribute(Object object, String name) {
        if (fakeAttributes == null) {
            return false;
        }
        List<String> result = fakeAttributes.get(object.getClass());
        if (result == null) {
            result = fakeAttributes.get(Object.class);
        }
        if (result == null) {
            return false;
        } else {
            return result.contains(name);
        }
    }


    /**
     * Set the fake attributes.
     *
     * @param fakeAttributes The new fake attributes.
     */
    public void setFakeAttributes(Map<Class<?>, List<String>> fakeAttributes) {

        this.fakeAttributes = fakeAttributes;

    }


    /**
     * Return the XMLReader to be used for parsing the input document.
     *
     * FIX ME: there is a bug in JAXP/XERCES that prevent the use of a
     * parser that contains a schema with a DTD.
     * @return the XML reader
     * @exception SAXException if no XMLReader can be instantiated
     */
    public XMLReader getXMLReader() throws SAXException {
        if (reader == null) {
            reader = getParser().getXMLReader();
            reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
            reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        }

        reader.setDTDHandler(this);
        reader.setContentHandler(this);

        EntityResolver entityResolver = getEntityResolver();
        if (entityResolver == null) {
            entityResolver = this;
        }

        // Wrap the resolver so we can perform ${...} property replacement
        if (entityResolver instanceof EntityResolver2) {
            entityResolver = new EntityResolver2Wrapper((EntityResolver2) entityResolver, source, classLoader);
        } else {
            entityResolver = new EntityResolverWrapper(entityResolver, source, classLoader);
        }

        reader.setEntityResolver(entityResolver);

        reader.setProperty("http://xml.org/sax/properties/lexical-handler", this);

        reader.setErrorHandler(this);
        return reader;
    }

    // ------------------------------------------------- ContentHandler Methods
    // ... (rest of file unchanged) 
}