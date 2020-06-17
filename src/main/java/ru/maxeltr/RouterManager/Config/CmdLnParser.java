/*
 * The MIT License
 *
 * Copyright 2020 Maxim Eltratov <Maxim.Eltratov@yandex.ru>.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package ru.maxeltr.RouterManager.Config;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;
import org.kohsuke.args4j.spi.StringArrayOptionHandler;

/**
 *
 * @author Maxim Eltratov <Maxim.Eltratov@yandex.ru>
 */
public class CmdLnParser {

    private static final Logger logger = Logger.getLogger(CmdLineParser.class.getName());

    @Option(name = "-add", handler = StringArrayOptionHandler.class, usage = "add MAC and its alias (-add MAC alias)")
    private List<String> macToAdd = new ArrayList<String>();

    @Option(name = "-del", handler = StringArrayOptionHandler.class, usage = "remove MAC by its alias")
    private List<String> macToDel = new ArrayList<String>();

    @Option(name = "-on", handler = StringArrayOptionHandler.class, usage = "turn on WI-FI for a alias")
    private List<String> turnOn = new ArrayList<String>();

    @Option(name = "-off", handler = StringArrayOptionHandler.class, usage = "turn off WI-FI for a alias")
    private List<String> turnOff = new ArrayList<String>();

    CmdLineParser parser;

    Config config;

    CmdLnParser(Config config) {
        this.parser = new CmdLineParser(this);
        this.config = config;
    }

    public void parse(String[] args) {
        try {
            this.parser.parseArgument(args);
        } catch (CmdLineException ex) {
            logger.log(Level.SEVERE, "Cannot parse command line arguments", ex);

            return;
        }

        if (this.macToAdd.size() > 0) {
            this.addMac(this.macToAdd);
            this.config.saveConfigToFile();
        }

        if (this.macToDel.size() > 0) {
            this.delMac(this.macToDel);
            this.config.saveConfigToFile();
        }

        if (this.turnOn.size() > 0) {
            this.config.ON_LIST = this.turnOn;
        }

        if (this.turnOff.size() > 0) {
            this.config.OFF_LIST = this.turnOff;
        }
    }

    private void addMac(List<String> value) {
        for (int i = 0; i < value.size(); i = i + 2) {
            this.config.setProperty(value.get(i + 1), value.get(i));
        }
    }

    private void delMac(List<String> value) {
        //TODO
    }
}
