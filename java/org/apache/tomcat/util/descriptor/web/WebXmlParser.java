```java
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
package org.apache.tomcat.util.descriptor.web;

import java.io.IOException;
import java.net.URL;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.descriptor.DigesterFactory;
import org.apache.tomcat.util.descriptor.InputSourceUtil;
import org.apache.tomcat.util.descriptor.XmlErrorHandler;
import org.apache.tomcat.util.digester.Digester;
import org.apache.tomcat.util.res.StringManager;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;

public class WebXmlParser {

    private final Log log = LogFactory.getLog(WebXmlParser.class); // must not be static

    /**
     * The string resources for this package.
     */
    private static final StringManager sm =
        StringManager.getManager(Constants.PACKAGE_NAME);

    /**
     * The <code>Digester</code> we will use to process web application
     * deployment descriptor files.
     */
    private final Digester webDigester;
    private final WebRuleSet webRuleSet;

    /**
     * The <code>Digester</code> we will use to process web fragment
     * deployment descriptor files.
     */
    private final Digester webFragmentDigester;
    private final WebRuleSet webFragmentRuleSet;


    public WebXmlParser(boolean namespaceAware, boolean validation,
            boolean blockExternal) {
        webRuleSet = new WebRuleSet(false);
        webDigester = DigesterFactory.newDigester(validation,
                namespaceAware, webRuleSet, blockExternal);
        try {
            webDigester.setFeature("http://xml.org/sax/features/external-general-entities", false);
            webDigester.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            webDigester.setFeature("http://apache.org/xml/features/nonvalid