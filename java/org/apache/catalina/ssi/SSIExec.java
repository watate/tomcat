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
package org.apache.catalina.ssi;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.regex.Pattern;

import org.apache.catalina.util.IOTools;
import org.apache.tomcat.util.res.StringManager;
/**
 * Implements the Server-side #exec command
 *
 * @author Bip Thelin
 * @author Amy Roh
 * @author Paul Speed
 * @author Dan Sandberg
 * @author David Becker
 */
public class SSIExec implements SSICommand {
    private static final StringManager sm = StringManager.getManager(SSIExec.class);
    protected final SSIInclude ssiInclude = new SSIInclude();
    protected static final int BUFFER_SIZE = 1024;

    /**
     * Pattern that matches only safe characters for command execution.
     * Allows alphanumeric characters, hyphens, underscores, dots, forward slashes,
     * spaces, and equals signs. Rejects shell metacharacters such as
     * ;, |, &, $, `, (, ), {, }, <, >, !, ~, ^, *, ?, [, ], \, ", ', newline, etc.
     */
    private static final Pattern SAFE_COMMAND_PATTERN =
            Pattern.compile("^[a-zA-Z0-9\\-_./= ]+$");

    /**
     * Validates that the command string does not contain dangerous shell metacharacters.
     *
     * @param command the command string to validate
     * @return true if the command is considered safe, false otherwise
     */
    private static boolean isValidCommand(String command) {
        if (command == null || command.isEmpty()) {
            return false;
        }
        // Reject commands with path traversal
        if (command.contains("..")) {
            return false;
        }
        // Only allow safe characters
        return SAFE_COMMAND_PATTERN.matcher(command).matches();
    }


    /**
     * @see SSICommand
     */
    @Override
    public long process(SSIMediator ssiMediator, String commandName,
            String[] paramNames, String[] paramValues, PrintWriter writer) {
        long lastModified = 0;
        String configErrMsg = ssiMediator.getConfigErrMsg();
        String paramName = paramNames[0];
        String paramValue = paramValues[0];
        String substitutedValue = ssiMediator.substituteVariables(paramValue);
        if (paramName.equalsIgnoreCase("cgi")) {
            lastModified = ssiInclude.process(ssiMediator, "include",
                    new String[]{"virtual"}, new String[]{substitutedValue},
                    writer);
        } else if (paramName.equalsIgnoreCase("cmd")) {
            if (!isValidCommand(substitutedValue)) {
                ssiMediator.log(sm.getString("ssiExec.executeFailed", substitutedValue),
                        new IOException("Command rejected: contains invalid characters or patterns"));
                writer.write(configErrMsg);
                return lastModified;
            }
            boolean foundProgram = false;
            try {
                ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", substitutedValue);
                pb.redirectErrorStream(false);
                Process proc = pb.start();
                foundProgram = true;
                BufferedReader stdOutReader = new BufferedReader(
                        new InputStreamReader(proc.getInputStream()));
                BufferedReader stdErrReader = new BufferedReader(
                        new InputStreamReader(proc.getErrorStream()));
                char[] buf = new char[BUFFER_SIZE];
                IOTools.flow(stdErrReader, writer, buf);
                IOTools.flow(stdOutReader, writer, buf);
                proc.waitFor();
                lastModified = System.currentTimeMillis();
            } catch (InterruptedException e) {
                ssiMediator.log(sm.getString("ssiExec.executeFailed", substitutedValue), e);
                writer.write(configErrMsg);
            } catch (IOException e) {
                if (!foundProgram) {
                    // Apache doesn't output an error message if it can't find
                    // a program
                }
                ssiMediator.log(sm.getString("ssiExec.executeFailed", substitutedValue), e);
            }
        }
        return lastModified;
    }
}