package burp.util;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;

import java.io.PrintWriter;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Utils {
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;

    // 参考burpfastjsonscan
    public static boolean isUrlBlackListSuffix(String burpUrl) {
        String noParameterUrl = burpUrl.split("\\?")[0];
        String urlSuffix = noParameterUrl.substring(noParameterUrl.lastIndexOf(".") + 1);

        List<String> suffixList = getSuffix();
        if (suffixList == null || suffixList.size() == 0) {
            return false;
        }

        for (String s : suffixList) {
            if (s.equalsIgnoreCase(urlSuffix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 判断是否查找的到指定的域名
     *
     * @param domainName     需匹配的域名
     * @param domainNameList 待匹配的域名列表
     * @return
     */
    public static Boolean isMatchDomainName(String domainName, List<String> domainNameList) {
        domainName = domainName.trim();

        if (domainName.length() <= 0) {
            return false;
        }

        if (domainNameList == null || domainNameList.size() <= 0) {
            return false;
        }

        if (domainName.contains(":")) {
            domainName = domainName.substring(0, domainName.indexOf(":"));
        }

        String reverseDomainName = new StringBuffer(domainName).reverse().toString();

        for (String domainName2 : domainNameList) {
            domainName2 = domainName2.trim();

            if (domainName2.length() <= 0) {
                continue;
            }

            if (domainName2.contains(":")) {
                domainName2 = domainName2.substring(0, domainName2.indexOf(":"));
            }

            String reverseDomainName2 = new StringBuffer(domainName2).reverse().toString();

            if (domainName.equals(domainName2)) {
                return true;
            }

            if (reverseDomainName.contains(".") && reverseDomainName2.contains(".")) {
                List<String> splitDomainName = new ArrayList<String>(Arrays.asList(reverseDomainName.split("[.]")));

                List<String> splitDomainName2 = new ArrayList<String>(Arrays.asList(reverseDomainName2.split("[.]")));

                if (splitDomainName.size() <= 0 || splitDomainName2.size() <= 0) {
                    continue;
                }

                if (splitDomainName.size() < splitDomainName2.size()) {
                    for (int i = splitDomainName.size(); i < splitDomainName2.size(); i++) {
                        splitDomainName.add("*");
                    }
                }

                if (splitDomainName.size() > splitDomainName2.size()) {
                    for (int i = splitDomainName2.size(); i < splitDomainName.size(); i++) {
                        splitDomainName2.add("*");
                    }
                }

                int ii = 0;
                for (int i = 0; i < splitDomainName.size(); i++) {
                    if (splitDomainName2.get(i).equals("*")) {
                        ii = ii + 1;
                    } else if (splitDomainName.get(i).equals(splitDomainName2.get(i))) {
                        ii = ii + 1;
                    }
                }

                if (ii == splitDomainName.size()) {
                    return true;
                }
            }
        }
        return false;
    }

    // 获取后缀列表
    public static List<String> getSuffix() {
        List<String> suffix = new ArrayList<>();
        suffix.add(".js");
        suffix.add(".css");
        suffix.add(".jpg");
        suffix.add(".png");
        suffix.add(".gif");
        suffix.add(".ico");
        suffix.add(".svg");
        suffix.add(".woff");
        suffix.add(".ttf");
        suffix.add(".eot");
        suffix.add(".woff2");
        suffix.add(".otf");
        suffix.add(".mp4");
        suffix.add(".mp3");
        suffix.add(".avi");
        suffix.add(".flv");
        suffix.add(".swf");
        suffix.add(".webp");
        suffix.add(".zip");
        suffix.add(".rar");
        suffix.add(".7z");
        suffix.add(".gz");
        suffix.add(".tar");
        suffix.add(".exe");
        suffix.add(".pdf");
        suffix.add(".doc");
        suffix.add(".docx");
        suffix.add(".xls");
        suffix.add(".xlsx");
        suffix.add(".ppt");
        suffix.add(".pptx");
        suffix.add(".txt");
        suffix.add(".xml");
        suffix.add(".apk");
        suffix.add(".ipa");
        suffix.add(".dmg");
        suffix.add(".iso");
        suffix.add(".img");
        suffix.add(".torrent");
        suffix.add(".jar");
        suffix.add(".war");
        suffix.add(".py");
        return suffix;
    }


    // 返回当前时间戳
    public static String getTimeNow() {
        return String.valueOf(System.currentTimeMillis() / 1000);
    }

    // 替换字符串中的特殊字符
    public static String ReplaceChar(String input) {
        // 使用正则表达式替换特殊字符
        return input.replaceAll("[\\n\\r]", "");
    }

    // 去除字符串两边的双引号
    public static String RemoveQuotes(String input) {
        // 去除字符串两边的双引号
        if (input.startsWith("\"") && input.endsWith("\"")) {
            input = input.substring(1, input.length() - 1);
        }

        return input;
    }

    // 对字符串进行url编码
    public static String UrlEncode(String input) {
        return URLEncoder.encode(input);
    }

    // 从HTML响应体中提取标题
    public static String extractTitle(String responseBody) {
        String title = "";

        String regex = "<title(.*?)>(.*?)</title>";
        Pattern p = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(responseBody);
        while (m.find()) {
            title = m.group(2);// 注意
            if (title != null && !title.equals("")) {
                return title;
            }
        }

        String regex1 = "<h[1-6](.*?)>(.*?)</h[1-6]>";
        Pattern ph = Pattern.compile(regex1, Pattern.CASE_INSENSITIVE);
        Matcher mh = ph.matcher(responseBody);
        while (mh.find()) {
            title = mh.group(2);
            if (title != null && !title.equals("")) {
                return title;
            }
        }
        return title;
    }

    // 对字符串进行utf-8编码
    public static String Utf8Encode(String originalString) {
        byte[] utf8Bytes = originalString.getBytes(StandardCharsets.UTF_8); // 使用UTF-8编码转换成字节数组
        String decodedString = new String(utf8Bytes, StandardCharsets.UTF_8);
        return decodedString;
    }

    // 获取当前时间
    public static String getCurrentTime() {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return simpleDateFormat.format(new Date());
    }

    /*
     * http://host:port/path/file.jpg -> http://host:port/path/
     * 获取路径排除文件名
     */
    public static String getUrlWithoutFilename(URL url) {
        String urlRootPath = getUrlRootPath(url);
        String path = url.getPath();

        if (path.length() == 0) {
            path = "/";
        }

        if (url.getFile().endsWith("/?format=openapi")) { //对django swagger做单独处理
            return urlRootPath + url.getFile();
        }

        if (path.endsWith("/")) {
            return urlRootPath + path;
        } else {
            return urlRootPath + path.substring(0, path.lastIndexOf("/") + 1);
        }
    }

    /**
     * 获取根目录的 URL
     */
    public static String getUrlRootPath(URL url) {
        return url.getProtocol() + "://" + url.getHost() + ":" + url.getPort();
    }

}
