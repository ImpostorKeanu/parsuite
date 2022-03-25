<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

    <xsl:template match="/">
        <xsl:copy>
            <xsl:apply-templates/>
        </xsl:copy>
    </xsl:template>

    <xsl:template match="/nmaprun">
        <nmaprun>
            <xsl:copy-of select="@*|b/@*"/>
            <xsl:copy-of select="/nmaprun/scaninfo"/>
            <xsl:copy-of select="/nmaprun/taskbegin"/>
            <xsl:copy-of select="/nmaprun/taskend"/>
            <!-- Capture all "up" hosts in ping scans -->
            <xsl:if test="/nmaprun/taskbegin[@task='Ping Scan']">
                <xsl:for-each select="//host/status[@state='up']">
                    <xsl:copy-of select=".."/>
                </xsl:for-each>
            </xsl:if>
            <xsl:if test="/nmaprun/taskbegin[@task!='Ping Scan']">
                <xsl:for-each select="//host">
                    <xsl:choose>
                        <!-- When the host has open ports -->
                        <!-- Note that "closed" actually indicates that the port is accessible but no service is listening -->
                    <xsl:when test="./ports/port/state[@state='open' or @state='closed']">
                        <xsl:copy select=".">
                            <xsl:copy-of select="@*"/>
                            <xsl:copy-of select="./status"/>
                            <xsl:copy-of select="./address"/>
                            <xsl:copy-of select="./hostnames"/>
                            <xsl:copy-of select="./times"/>
                            <xsl:for-each select="./ports/port/state[@state='open']">
                                <ports>
                                    <xsl:copy-of select="../../extraports"/>
                                    <xsl:for-each select="..">
                                        <xsl:copy-of select="."/>
                                    </xsl:for-each>
                                </ports>
                            </xsl:for-each>
                        </xsl:copy>
                    </xsl:when>
                    <!-- When no ports are open but hostnames are available -->
                    <xsl:when test=".//hostname">
                        <xsl:copy select="../..">
                            <xsl:copy-of select="@*"/>
                            <!-- Set to up to ensure that hostnames are captured -->
                            <status state="up" reason="user-set" reason_ttl="0"/>
                            <xsl:copy-of select="./address"/>
                            <xsl:copy-of select="./hostnames"/>
                            <xsl:copy-of select="./times"/>
                            <ports/>
                        </xsl:copy>
                    </xsl:when>
                </xsl:choose>
                </xsl:for-each>
            </xsl:if>
        </nmaprun>
    </xsl:template>

</xsl:stylesheet>
