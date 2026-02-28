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
import java.io.StringReader;
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

            factory.setXIncludeAware(false);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

            factory.setValidating(validating);
            if (validating) {
                // Enable DTD validation
                factory.setFeature("http://xml.org/sax/features/validation", true);
                // Enable schema validation
                factory.setFeature("http://apache.org/xml/features/validation/schema", true);
            }
        }
        return factory;
    }

    public void setFeature(String feature, boolean value) throws ParserConfigurationException,
            SAXNotRecognizedException, SAXNotSupportedException {

        getFactory().setFeature(feature, value);

    }

    public Log getLogger() {

        return log;

    }

    public void setLogger(Log log) {

        this.log = log;

    }

    public Log getSAXLogger() {

        return saxLog;
    }

    public void setSAXLogger(Log saxLog) {

        this.saxLog = saxLog;
    }

    public String getMatch() {

        return match;

    }

    public boolean getNamespaceAware() {
        return this.namespaceAware;
    }

    public void setNamespaceAware(boolean namespaceAware) {
        this.namespaceAware = namespaceAware;
    }

    public void setPublicId(String publicId) {
        this.publicId = publicId;
    }

    public String getPublicId() {
        return this.publicId;
    }

    public SAXParser getParser() {

        if (parser != null) {
            return parser;
        }

        try {
            parser = getFactory().newSAXParser();
            try {
                parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            } catch (SAXNotRecognizedException | SAXNotSupportedException ignored) {
            }
            try {
                parser.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            } catch (SAXNotRecognizedException | SAXNotSupportedException ignored) {
            }
        } catch (Exception e) {
            log.error(sm.getString("digester.createParserError"), e);
            return null;
        }

        return parser;
    }

    public Object getProperty(String property)
            throws SAXNotRecognizedException, SAXNotSupportedException {

        return getParser().getProperty(property);
    }

    public Rules getRules() {
        if (this.rules == null) {
            this.rules = new RulesBase();
            this.rules.setDigester(this);
        }
        return this.rules;
    }

    public void setRules(Rules rules) {
        this.rules = rules;
        this.rules.setDigester(this);
    }

    public boolean getUseContextClassLoader() {
        return useContextClassLoader;
    }

    public void setUseContextClassLoader(boolean use) {

        useContextClassLoader = use;

    }

    public boolean getValidating() {
        return this.validating;
    }

    public void setValidating(boolean validating) {
        this.validating = validating;
    }

    public boolean getRulesValidation() {
        return this.rulesValidation;
    }

    public void setRulesValidation(boolean rulesValidation) {
        this.rulesValidation = rulesValidation;
    }

    public Map<Class<?>, List<String>> getFakeAttributes() {
        return this.fakeAttributes;
    }

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

    public void setFakeAttributes(Map<Class<?>, List<String>> fakeAttributes) {

        this.fakeAttributes = fakeAttributes;

    }

    public XMLReader getXMLReader() throws SAXException {
        if (reader == null) {
            reader = getParser().getXMLReader();
        }

        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

        reader.setDTDHandler(this);
        reader.setContentHandler(this);

        EntityResolver entityResolver = getEntityResolver();
        if (entityResolver == null) {
            entityResolver = this;
        }

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

    @Override
    public void characters(char buffer[], int start, int length) throws SAXException {

        if (saxLog.isDebugEnabled()) {
            saxLog.debug("characters(" + new String(buffer, start, length) + ")");
        }

        bodyText.append(buffer, start, length);

    }

    @Override
    public void endDocument() throws SAXException {

        if (saxLog.isDebugEnabled()) {
            if (getCount() > 1) {
                saxLog.debug("endDocument():  " + getCount() + " elements left");
            } else {
                saxLog.debug("endDocument()");
            }
        }

        while (getCount() > 1) {
            pop();
        }

        for (Rule rule : getRules().rules()) {
            try {
                rule.finish();
            } catch (Exception e) {
                log.error(sm.getString("digester.error.finish"), e);
                throw createSAXException(e);
            } catch (Error e) {
                log.error(sm.getString("digester.error.finish"), e);
                throw e;
            }
        }

        clear();

    }

    @Override
    public void endElement(String namespaceURI, String localName, String qName)
            throws SAXException {

        boolean debug = log.isDebugEnabled();

        if (debug) {
            if (saxLog.isDebugEnabled()) {
                saxLog.debug("endElement(" + namespaceURI + "," + localName + "," + qName + ")");
            }
            log.debug("  match='" + match + "'");
            log.debug("  bodyText='" + bodyText + "'");
        }

        bodyText = updateBodyText(bodyText);

        String name = localName;
        if ((name == null) || (name.length() < 1)) {
            name = qName;
        }

        List<Rule> rules = matches.pop();
        if ((rules != null) && (rules.size() > 0)) {
            String bodyText = this.bodyText.toString().intern();
            for (Rule value : rules) {
                try {
                    Rule rule = value;
                    if (debug) {
                        log.debug("  Fire body() for " + rule);
                    }
                    rule.body(namespaceURI, name, bodyText);
                } catch (Exception e) {
                    log.error(sm.getString("digester.error.body"), e);
                    throw createSAXException(e);
                } catch (Error e) {
                    log.error(sm.getString("digester.error.body"), e);
                    throw e;
                }
            }
        } else {
            if (debug) {
                log.debug(sm.getString("digester.noRulesFound", match));
            }
            if (rulesValidation) {
                log.warn(sm.getString("digester.noRulesFound", match));
            }
        }

        bodyText = bodyTexts.pop();

        if (rules != null) {
            for (int i = 0; i < rules.size(); i++) {
                int j = (rules.size() - i) - 1;
                try {
                    Rule rule = rules.get(j);
                    if (debug) {
                        log.debug("  Fire end() for " + rule);
                    }
                    rule.end(namespaceURI, name);
                } catch (Exception e) {
                    log.error(sm.getString("digester.error.end"), e);
                    throw createSAXException(e);
                } catch (Error e) {
                    log.error(sm.getString("digester.error.end"), e);
                    throw e;
                }
            }
        }

        int slash = match.lastIndexOf('/');
        if (slash >= 0) {
            match = match.substring(0, slash);
        } else {
            match = "";
        }

    }

    @Override
    public void endPrefixMapping(String prefix) throws SAXException {

        if (saxLog.isDebugEnabled()) {
            saxLog.debug("endPrefixMapping(" + prefix + ")");
        }

        ArrayStack<String> stack = namespaces.get(prefix);
        if (stack == null) {
            return;
        }
        try {
            stack.pop();
            if (stack.empty()) {
                namespaces.remove(prefix);
            }
        } catch (EmptyStackException e) {
            throw createSAXException(sm.getString("digester.emptyStackError"));
        }

    }

    @Override
    public void ignorableWhitespace(char buffer[], int start, int len) throws SAXException {

        if (saxLog.isDebugEnabled()) {
            saxLog.debug("ignorableWhitespace(" + new String(buffer, start, len) + ")");
        }

    }

    @Override
    public void processingInstruction(String target, String data) throws SAXException {

        if (saxLog.isDebugEnabled()) {
            saxLog.debug("processingInstruction('" + target + "','" + data + "')");
        }

    }

    public Locator getDocumentLocator() {

        return locator;

    }

    @Override
    public void setDocumentLocator(Locator locator) {

        if (saxLog.isDebugEnabled()) {
            saxLog.debug("setDocumentLocator(" + locator + ")");
        }

        this.locator = locator;

    }

    @Override
    public void skippedEntity(String name) throws SAXException {

        if (saxLog.isDebugEnabled()) {
            saxLog.debug("skippedEntity(" + name + ")");
        }

    }

    @Override
    public void startDocument() throws SAXException {

        if (saxLog.isDebugEnabled()) {
            saxLog.debug("startDocument()");
        }

        if (locator instanceof Locator2) {
            if (root instanceof DocumentProperties.Charset) {
                String enc = ((Locator2) locator).getEncoding();
                if (enc != null) {
                    try {
                        ((DocumentProperties.Charset) root).setCharset(B2CConverter.getCharset(enc));
                    } catch (UnsupportedEncodingException e) {
                        log.warn(sm.getString("digester.encodingInvalid", enc), e);
                    }
                }
            }
        }

        configure();
    }

    @Override
    public void startElement(String namespaceURI, String localName, String qName, Attributes list)
            throws SAXException {
        boolean debug = log.isDebugEnabled();

        if (saxLog.isDebugEnabled()) {
            saxLog.debug("startElement(" + namespaceURI + "," + localName + "," + qName + ")");
        }

        list = updateAttributes(list);

        bodyTexts.push(bodyText);
        bodyText = new StringBuilder();

        String name = localName;
        if ((name == null) || (name.length() < 1)) {
            name = qName;
        }

        StringBuilder sb = new StringBuilder(match);
        if (match.length() > 0) {
            sb.append('/');
        }
        sb.append(name);
        match = sb.toString();
        if (debug) {
            log.debug("  New match='" + match + "'");
        }

        List<Rule> rules = getRules().match(namespaceURI, match);
        matches.push(rules);
        if ((rules != null) && (rules.size() > 0)) {
            for (Rule value : rules) {
                try {
                    Rule rule = value;
                    if (debug) {
                        log.debug("  Fire begin() for " + rule);
                    }
                    rule.begin(namespaceURI, name, list);
                } catch (Exception e) {
                    log.error(sm.getString("digester.error.begin"), e);
                    throw createSAXException(e);
                } catch (Error e) {
                    log.error(sm.getString("digester.error.begin"), e);
                    throw e;
                }
            }
        } else {
            if (debug) {
                log.debug(sm.getString("digester.noRulesFound", match));
            }
        }

    }

    @Override
    public void startPrefixMapping(String prefix, String namespaceURI) throws SAXException {

        if (saxLog.isDebugEnabled()) {
            saxLog.debug("startPrefixMapping(" + prefix + "," + namespaceURI + ")");
        }

        ArrayStack<String> stack = namespaces.get(prefix);
        if (stack == null) {
            stack = new ArrayStack<>();
            namespaces.put(prefix, stack);
        }
        stack.push(namespaceURI);

    }

    @Override
    public void notationDecl(String name, String publicId, String systemId) {

        if (saxLog.isDebugEnabled()) {
            saxLog.debug("notationDecl(" + name + "," + publicId + "," + systemId + ")");
        }

    }

    @Override
    public void unparsedEntityDecl(String name, String publicId, String systemId, String notation) {

        if (saxLog.isDebugEnabled()) {
            saxLog.debug("unparsedEntityDecl(" + name + "," + publicId + "," + systemId + ","
                    + notation + ")");
        }

    }

    public void setEntityResolver(EntityResolver entityResolver) {
        this.entityResolver = entityResolver;
    }

    public EntityResolver getEntityResolver() {
        return entityResolver;
    }

    @Override
    public InputSource resolveEntity(String name, String publicId, String baseURI, String systemId)
            throws SAXException, IOException {

        if (saxLog.isDebugEnabled()) {
            saxLog.debug(
                    "resolveEntity('" + publicId + "', '" + systemId + "', '" + baseURI + "')");
        }

        return new InputSource(new StringReader(""));
    }

    @Override
    public void startDTD(String name, String publicId, String systemId) throws SAXException {
        setPublicId(publicId);
    }

    @Override
    public void error(SAXParseException exception) throws SAXException {
        log.error(sm.getString("digester.parseError", Integer.valueOf(exception.getLineNumber()),
                Integer.valueOf(exception.getColumnNumber())), exception);
        if (errorHandler != null) {
            errorHandler.error(exception);
        }
    }

    @Override
    public void fatalError(SAXParseException exception) throws SAXException {
        log.error(sm.getString("digester.parseErrorFatal", Integer.valueOf(exception.getLineNumber()),
                Integer.valueOf(exception.getColumnNumber())), exception);
        if (errorHandler != null) {
            errorHandler.fatalError(exception);
        }
    }

    @Override
    public void warning(SAXParseException exception) throws SAXException {
        log.error(sm.getString("digester.parseWarning", Integer.valueOf(exception.getLineNumber()),
                Integer.valueOf(exception.getColumnNumber()), exception));
        if (errorHandler != null) {
            errorHandler.warning(exception);
        }

    }

    public Object parse(File file) throws IOException, SAXException {
        configure();
        InputSource input = new InputSource(new FileInputStream(file));
        input.setSystemId("file://" + file.getAbsolutePath());
        getXMLReader().parse(input);
        return root;
    }

    public Object parse(InputSource input) throws IOException, SAXException {
        configure();
        getXMLReader().parse(input);
        return root;
    }

    public Object parse(InputStream input) throws IOException, SAXException {
        configure();
        InputSource is = new InputSource(input);
        getXMLReader().parse(is);
        return root;
    }

    public void register(String publicId, String entityURL) {

        if (log.isDebugEnabled()) {
            log.debug("register('" + publicId + "', '" + entityURL + "'");
        }
        entityValidator.put(publicId, entityURL);

    }

    public void addRule(String pattern, Rule rule) {

        rule.setDigester(this);
        getRules().add(pattern, rule);

    }

    public void addRuleSet(RuleSet ruleSet) {
        ruleSet.addRuleInstances(this);
    }

    public void addCallMethod(String pattern, String methodName) {

        addRule(pattern, new CallMethodRule(methodName));

    }

    public void addCallMethod(String pattern, String methodName, int paramCount) {

        addRule(pattern, new CallMethodRule(methodName, paramCount));

    }

    public void addCallParam(String pattern, int paramIndex) {

        addRule(pattern, new CallParamRule(paramIndex));

    }

    public void addFactoryCreate(String pattern, ObjectCreationFactory creationFactory,
            boolean ignoreCreateExceptions) {

        creationFactory.setDigester(this);
        addRule(pattern, new FactoryCreateRule(creationFactory, ignoreCreateExceptions));

    }

    public void addObjectCreate(String pattern, String className) {

        addRule(pattern, new ObjectCreateRule(className));

    }

    public void addObjectCreate(String pattern, String className, String attributeName) {

        addRule(pattern, new ObjectCreateRule(className, attributeName));

    }

    public void addSetNext(String pattern, String methodName, String paramType) {

        addRule(pattern, new SetNextRule(methodName, paramType));

    }

    public void addSetProperties(String pattern) {

        addRule(pattern, new SetPropertiesRule());

    }

    public void addSetProperties(String pattern, String[] excludes) {

        addRule(pattern, new SetPropertiesRule(excludes));

    }

    public void clear() {

        match = "";
        bodyTexts.clear();
        params.clear();
        publicId = null;
        stack.clear();
        log = null;
        saxLog = null;
        configured = false;

    }

    public void reset() {
        root = null;
        setErrorHandler(null);
        clear();
    }

    public Object peek() {
        try {
            return stack.peek();
        } catch (EmptyStackException e) {
            log.warn(sm.getString("digester.emptyStack"));
            return null;
        }
    }

    public Object peek(int n) {
        try {
            return stack.peek(n);
        } catch (EmptyStackException e) {
            log.warn(sm.getString("digester.emptyStack"));
            return null;
        }
    }

    public Object pop() {
        try {
            return stack.pop();
        } catch (EmptyStackException e) {
            log.warn(sm.getString("digester.emptyStack"));
            return null;
        }
    }

    public void push(Object object) {

        if (stack.size() == 0) {
            root = object;
        }
        stack.push(object);

    }

    public Object getRoot() {
        return root;
    }

    protected void configure() {

        if (configured) {
            return;
        }

        log = LogFactory.getLog("org.apache.tomcat.util.digester.Digester");
        saxLog = LogFactory.getLog("org.apache.tomcat.util.digester.Digester.sax");

        configured = true;
    }

    public Object peekParams() {
        try {
            return params.peek();
        } catch (EmptyStackException e) {
            log.warn(sm.getString("digester.emptyStack"));
            return null;
        }
    }

    public Object popParams() {
        try {
            if (log.isTraceEnabled()) {
                log.trace("Popping params");
            }
            return params.pop();
        } catch (EmptyStackException e) {
            log.warn(sm.getString("digester.emptyStack"));
            return null;
        }
    }

    public void pushParams(Object object) {
        if (log.isTraceEnabled()) {
            log.trace("Pushing params");
        }
        params.push(object);

    }

    public SAXException createSAXException(String message, Exception e) {
        if ((e != null) && (e instanceof InvocationTargetException)) {
            Throwable t = e.getCause();
            if (t instanceof ThreadDeath) {
                throw (ThreadDeath) t;
            }
            if (t instanceof VirtualMachineError) {
                throw (VirtualMachineError) t;
            }
            if (t instanceof Exception) {
                e = (Exception) t;
            }
        }
        if (locator != null) {
            String error = sm.getString("digester.errorLocation",
                    Integer.valueOf(locator.getLineNumber()),
                    Integer.valueOf(locator.getColumnNumber()), message);
            if (e != null) {
                return new SAXParseException(error, locator, e);
            } else {
                return new SAXParseException(error, locator);
            }
        }
        log.error(sm.getString("digester.noLocator"));
        if (e != null) {
            return new SAXException(message, e);
        } else {
            return new SAXException(message);
        }
    }

    public SAXException createSAXException(Exception e) {
        if (e instanceof InvocationTargetException) {
            Throwable t = e.getCause();
            if (t instanceof ThreadDeath) {
                throw (ThreadDeath) t;
            }
            if (t instanceof VirtualMachineError) {
                throw (VirtualMachineError) t;
            }
            if (t instanceof Exception) {
                e = (Exception) t;
            }
        }
        return createSAXException(e.getMessage(), e);
    }

    public SAXException createSAXException(String message) {
        return createSAXException(message, null);
    }

    private Attributes updateAttributes(Attributes list) {

        if (list.getLength() == 0) {
            return list;
        }

        AttributesImpl newAttrs = new AttributesImpl(list);
        int nAttributes = newAttrs.getLength();
        for (int i = 0; i < nAttributes; ++i) {
            String value = newAttrs.getValue(i);
            try {
                newAttrs.setValue(i, IntrospectionUtils.replaceProperties(value, null, source, getClassLoader()).intern());
            } catch (Exception e) {
                log.warn(sm.getString("digester.failedToUpdateAttributes", newAttrs.getLocalName(i), value), e);
            }
        }

        return newAttrs;
    }

    private StringBuilder updateBodyText(StringBuilder bodyText) {
        String in = bodyText.toString();
        String out;
        try {
            out = IntrospectionUtils.replaceProperties(in, null, source, getClassLoader());
        } catch (Exception e) {
            return bodyText;
        }

        if (out == in) {
            return bodyText;
        } else {
            return new StringBuilder(out);
        }
    }

    private static class EntityResolverWrapper implements EntityResolver {

        private final EntityResolver entityResolver;
        private final PropertySource[] source;
        private final ClassLoader classLoader;

        EntityResolverWrapper(EntityResolver entityResolver, PropertySource[] source, ClassLoader classLoader) {
            this.entityResolver = entityResolver;
            this.source = source;
            this.classLoader = classLoader;
        }

        @Override
        public InputSource resolveEntity(String publicId, String systemId)
                throws SAXException, IOException {
            publicId = replace(publicId);
            systemId = replace(systemId);
            return entityResolver.resolveEntity(publicId, systemId);
        }

        protected String replace(String input) {
            try {
                return IntrospectionUtils.replaceProperties(input, null, source, classLoader);
            } catch (Exception e) {
                return input;
            }
        }
    }

    private static class EntityResolver2Wrapper extends EntityResolverWrapper implements EntityResolver2 {

        private final EntityResolver2 entityResolver2;

        EntityResolver2Wrapper(EntityResolver2 entityResolver, PropertySource[] source,
                ClassLoader classLoader) {
            super(entityResolver, source, classLoader);
            this.entityResolver2 = entityResolver;
        }

        @Override
        public InputSource getExternalSubset(String name, String baseURI)
                throws SAXException, IOException {
            name = replace(name);
            baseURI = replace(baseURI);
            return entityResolver2.getExternalSubset(name, baseURI);
        }

        @Override
        public InputSource resolveEntity(String name, String publicId, String baseURI,
                String systemId) throws SAXException, IOException {
            name = replace(name);
            publicId = replace(publicId);
            baseURI = replace(baseURI);
            systemId = replace(systemId);
            return entityResolver2.resolveEntity(name, publicId, baseURI, systemId);
        }
    }
}