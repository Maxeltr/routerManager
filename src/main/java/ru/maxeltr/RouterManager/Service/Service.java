/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ru.maxeltr.RouterManager.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.FormElement;
import org.jsoup.select.Elements;
import ru.maxeltr.RouterManager.Config.Config;

public class Service {

    Config config;

    HttpClient client;

    HttpClientContext context;

    CryptService cryptService;

    private static final Logger logger = Logger.getLogger(Service.class.getName());

    public Service(Config config, CryptService cryptService) {
        this.config = config;
        this.cryptService = cryptService;
        this.context = HttpClientContext.create();
    }

    private void createClient() {
        CredentialsProvider credsProvider = new BasicCredentialsProvider();
        credsProvider.setCredentials(
                AuthScope.ANY,
                new UsernamePasswordCredentials(
                        new String(cryptService.decrypt(this.config.getProperty("Login", ""))),
                        new String(cryptService.decrypt(this.config.getProperty("Password", "")))
//                        this.config.getProperty("Login", "admin"),
//                        this.config.getProperty("Password", "admin")
                )
        );
        this.context.setCredentialsProvider(credsProvider);

        AuthCache authCache = new BasicAuthCache();
        HttpHost targetHost = new HttpHost("localhost", 8082, "http");
        authCache.put(targetHost, new BasicScheme());
        this.context.setAuthCache(authCache);

        this.client = HttpClientBuilder.create().build();
    }

    public int  turnOff() {
        int amount = 0;

        if (this.config.OFF_LIST.isEmpty()) {
            logger.log(Level.INFO, String.format("List to turn off is empty.%n"));

            return amount;
        }

        for (String macAlias : this.config.OFF_LIST) {
            String mac = this.config.getProperty(macAlias, "");
            if (mac.isEmpty()) {
                continue;
            }

            if (this.delMac(mac)) {
                amount++;
            }
        }

        return amount;
    }

    private boolean delMac(String mac) {
        Document doc = this.getPage("http://192.168.1.1/Advanced_ACL_Content.asp#ACLList");
        if (doc == null) {
            logger.log(Level.WARNING, String.format("Cannot get ACLList page.%n"));

            return false;
        }

        FormElement form = (FormElement) doc.select("form[name=form]").first();

        Elements selectOptions = form.select("select[name=ACLList_s]>option");
        int macNumberInList = -1;
        for (int i = 0; i < selectOptions.size(); i++) {
            if (selectOptions.get(i).text().equalsIgnoreCase(mac)) {
                macNumberInList = i;
                break;
            }
        }

        if (macNumberInList == -1) {
            logger.log(Level.WARNING, String.format("MAC %s is absent in list.%n", mac));

            return false;
        }

        String AddACLListUrl = "http://192.168.1.1/apply.cgi";
        URIBuilder builder = null;
        try {
            builder = new URIBuilder(AddACLListUrl);
        } catch (URISyntaxException ex) {
            Logger.getLogger(Service.class.getName()).log(Level.SEVERE, String.format("Cannot create UriBuilder for uri: %s.%n", AddACLListUrl), ex);

            return false;
        }
        builder.setParameter("current_page", "Advanced_ACL_Content.asp")
                .setParameter("next_page", "Advanced_WSecurity_Content.asp")
                .setParameter("next_host", "192.168.1.1")
                .setParameter("sid_list", "DeviceSecurity11a;")
                .setParameter("group_id", "ACLList")
                .setParameter("modified", "0")
                .setParameter("action_mode", " Del ")
                .setParameter("first_time", "")
                .setParameter("action_script", "")
                .setParameter("wl_macmode", "allow")
                .setParameter("wl_macnum_x_0", Integer.toString(selectOptions.size()))
                .setParameter("ACLList", " Del ")
                .setParameter("wl_maclist_x_0", "")
                .setParameter("ACLList_s", Integer.toString(macNumberInList));

        HttpGet query;
        try {
            query = new HttpGet(builder.build());
        } catch (URISyntaxException ex) {
            Logger.getLogger(Service.class.getName()).log(Level.SEVERE, String.format("Cannot create HttpGet.%n"), ex);

            return false;
        }

//        query.addHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9");
//        query.addHeader("Accept-Encoding", "gzip, deflate, sdch");
//        query.addHeader("Accept-Language", "ru,en;q=0.9");
////        query.addHeader("Authorization", "Basic YWRtaW46aGZHMjM3Rg==");
//        query.addHeader("Connection", "keep-alive");
//        query.addHeader("Host", "192.168.1.1");
//        query.addHeader("Referer", "http://192.168.1.1/Advanced_ACL_Content.asp");
//        query.addHeader("Upgrade-Insecure-Requests", "1");
//        query.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 YaBrowser/20.6.0.905 Yowser/2.5 Safari/537.36");

        HttpResponse response = this.executeQuery(query);
        if (response == null) {
            return false;
        }

        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode != 200) {
            logger.log(Level.WARNING, String.format("Cannot add MAC. Status code is %s.%n", statusCode));
        }

        try {
            response.getEntity().getContent().close();
        } catch (IOException | UnsupportedOperationException ex) {
            Logger.getLogger(Service.class.getName()).log(Level.SEVERE, null, ex);
        }

        logger.log(Level.INFO, String.format("MAC %s was deleted.%n", mac));

        return true;
    }

    private HttpResponse executeQuery(HttpUriRequest query) {
        if (this.client == null) {
            this.createClient();
        }

        HttpResponse response;
        try {
            response = this.client.execute(query, this.context);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Cannot execute query to %s.%n", query.getURI().getPath()), ex);

            return null;
        }

        return response;
    }

    public int turnOn() {
        int amount = 0;

        if (this.config.ON_LIST.isEmpty()) {
            logger.log(Level.INFO, String.format("List to turn on is empty.%n"));

            return amount;
        }

        for (String macAlias : this.config.ON_LIST) {
            String mac = this.config.getProperty(macAlias, "");
            if (mac.isEmpty()) {
                continue;
            }

            if (this.addMac(mac)) {
                amount++;
            }
        }

        return amount;
    }

    public void restart() {
        String AddACLListUrl = "http://192.168.1.1/apply.cgi";
        URIBuilder builder = null;
        try {
            builder = new URIBuilder(AddACLListUrl);
        } catch (URISyntaxException ex) {
            Logger.getLogger(Service.class.getName()).log(Level.SEVERE, String.format("Cannot create UriBuilder for uri: %s.%n", AddACLListUrl), ex);

            return;
        }
        builder .setParameter("action_mode", "Save&Restart ")
                .setParameter("current_page", "Basic_Operation_Content.asp")
                .setParameter("next_page", "Basic_SaveRestart.asp")
                .setParameter("sid_list", "General;")
                .setParameter("group_id", "")
                .setParameter("modified", "0")
                .setParameter("action", "Save&Restart");

        HttpGet query;
        try {
            query = new HttpGet(builder.build());
        } catch (URISyntaxException ex) {
            Logger.getLogger(Service.class.getName()).log(Level.SEVERE, String.format("Cannot create HttpGet.%n"), ex);

            return;
        }

        HttpResponse response = this.executeQuery(query);
        if (response == null) {
            return;
        }

        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode != 200) {
            logger.log(Level.WARNING, String.format("Cannot add MAC. Status code is %s.%n", statusCode));
        }

        try {
            response.getEntity().getContent().close();
        } catch (IOException | UnsupportedOperationException ex) {
            Logger.getLogger(Service.class.getName()).log(Level.SEVERE, null, ex);
        }

        logger.log(Level.INFO, String.format("Restart query was sent.%n"));
    }

    private void finish() {
        Document doc = this.getPage("http://192.168.1.1/Advanced_ACL_Content.asp#ACLList");
        if (doc == null) {
            logger.log(Level.INFO, String.format("Cannot get ACLList page.%n"));

            return;
        }

        FormElement form = (FormElement) doc.select("form[name=form]").first();

        Elements selectOptions = form.select("select[name=ACLList_s]>option");

        String AddACLListUrl = "http://192.168.1.1/apply.cgi";
        URIBuilder builder = null;
        try {
            builder = new URIBuilder(AddACLListUrl);
        } catch (URISyntaxException ex) {
            Logger.getLogger(Service.class.getName()).log(Level.SEVERE, String.format("Cannot create UriBuilder for uri: %s.%n", AddACLListUrl), ex);

            return;
        }
        builder.setParameter("current_page", "Advanced_ACL_Content.asp")
                .setParameter("next_page", "Advanced_WSecurity_Content.asp")
                .setParameter("next_host", "192.168.1.1")
                .setParameter("sid_list", "DeviceSecurity11a;")
                .setParameter("group_id", "")
                .setParameter("modified", "0")
                .setParameter("action_mode", " Finish ")
                .setParameter("first_time", "")
                .setParameter("action_script", "")
                .setParameter("wl_macmode", "allow")
                .setParameter("wl_macnum_x_0", Integer.toString(selectOptions.size()))
                .setParameter("wl_maclist_x_0", "")
                .setParameter("ACLList", " Finish ");

        HttpGet query;
        try {
            query = new HttpGet(builder.build());
        } catch (URISyntaxException ex) {
            Logger.getLogger(Service.class.getName()).log(Level.SEVERE, String.format("Cannot create HttpGet.%n"), ex);

            return;
        }

        HttpResponse response = this.executeQuery(query);
        if (response == null) {
            return;
        }

        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode != 200) {
            logger.log(Level.WARNING, String.format("Cannot add MAC. Status code is %s.%n", statusCode));
        }

        try {
            response.getEntity().getContent().close();
        } catch (IOException | UnsupportedOperationException ex) {
            Logger.getLogger(Service.class.getName()).log(Level.SEVERE, null, ex);
        }

        logger.log(Level.INFO, String.format("Finish query was sent.%n"));
    }

    private boolean addMac(String mac) {
        Document doc = this.getPage("http://192.168.1.1/Advanced_ACL_Content.asp#ACLList");
        if (doc == null) {
            logger.log(Level.INFO, String.format("Cannot get ACLList page.%n"));

            return false;
        }

        FormElement form = (FormElement) doc.select("form[name=form]").first();

        Elements selectOptions = form.select("select[name=ACLList_s]>option");
        for (int i = 0; i < selectOptions.size(); i++) {
            if (selectOptions.get(i).text().equalsIgnoreCase(mac)) {
                logger.log(Level.WARNING, String.format("MAC %s is in list already.%n", mac));

                return false;
            }
        }

        String AddACLListUrl = "http://192.168.1.1/apply.cgi";
        URIBuilder builder = null;
        try {
            builder = new URIBuilder(AddACLListUrl);
        } catch (URISyntaxException ex) {
            Logger.getLogger(Service.class.getName()).log(Level.SEVERE, String.format("Cannot create UriBuilder for uri: %s.%n", AddACLListUrl), ex);

            return false;
        }
        builder.setParameter("current_page", "Advanced_ACL_Content.asp")
                .setParameter("next_page", "Advanced_WSecurity_Content.asp")
                .setParameter("next_host", "192.168.1.1")
                .setParameter("sid_list", "DeviceSecurity11a;")
                .setParameter("group_id", "ACLList")
                .setParameter("modified", "0")
                .setParameter("action_mode", " Add ")
                .setParameter("first_time", "")
                .setParameter("action_script", "")
                .setParameter("wl_macmode", "allow")
                .setParameter("wl_macnum_x_0", Integer.toString(selectOptions.size()))
                .setParameter("ACLList", " Add ")
                .setParameter("wl_maclist_x_0", mac);

        HttpGet query;
        try {
            query = new HttpGet(builder.build());
        } catch (URISyntaxException ex) {
            Logger.getLogger(Service.class.getName()).log(Level.SEVERE, String.format("Cannot create HttpGet.%n"), ex);

            return false;
        }

//        query.addHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9");
//        query.addHeader("Accept-Encoding", "gzip, deflate, sdch");
//        query.addHeader("Accept-Language", "ru,en;q=0.9");
////        query.addHeader("Authorization", "Basic YWRtaW46aGZHMjM3Rg==");
//        query.addHeader("Connection", "keep-alive");
//        query.addHeader("Host", "192.168.1.1");
//        query.addHeader("Referer", "http://192.168.1.1/Advanced_ACL_Content.asp");
//        query.addHeader("Upgrade-Insecure-Requests", "1");
//        query.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 YaBrowser/20.6.0.905 Yowser/2.5 Safari/537.36");

        HttpResponse response = this.executeQuery(query);
        if (response == null) {
            return false;
        }

        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode != 200) {
            logger.log(Level.WARNING, String.format("Cannot add MAC. Status code is %s.%n", statusCode));
        }

        try {
            response.getEntity().getContent().close();
        } catch (IOException | UnsupportedOperationException ex) {
            Logger.getLogger(Service.class.getName()).log(Level.SEVERE, null, ex);
        }

        logger.log(Level.INFO, String.format("MAC %s was added.%n", mac));

        return true;
    }

    private Document getPage(String url) {
        HttpResponse response = this.executeQuery(new HttpGet(url));
        if (response == null) {
            return null;
        }

        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode != 200) {
            logger.log(Level.WARNING, String.format("Cannot get page. Status code is %s.%n", statusCode));

            return null;
        }

        StringBuffer tmp = new StringBuffer();
        try {
            String line;
            BufferedReader in = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            while ((line = in.readLine()) != null) {
                String decoded = new String(line.getBytes(), "UTF-8");
                tmp.append(" ").append(decoded);
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Cannot proccesing input stream.%n"), ex);

            return null;
        }

        try {
            response.getEntity().getContent().close();
        } catch (IOException | UnsupportedOperationException ex) {
            Logger.getLogger(Service.class.getName()).log(Level.SEVERE, null, ex);
        }

        Document doc = Jsoup.parse(String.valueOf(tmp));

        return doc;
    }
}
