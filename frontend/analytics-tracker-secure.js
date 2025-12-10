// ============================================
// ANALYTICS TRACKER - FRONTEND SEGURO
// ============================================
// Supermercado Compre Mais
// Versão: 2.0.0 - Segura e isolada

(function() {
    'use strict';
    
    // ============================================
    // CONFIGURAÇÃO (apenas URL da API)
    // ============================================
    
    const API_URL = 'https://compremais-landingpage.onrender.com'; // Backend 
    
    // Session ID gerado no cliente (não expõe dados sensíveis)
    const SESSION_ID = generateSessionId();
    
    // ============================================
    // FUNÇÕES AUXILIARES
    // ============================================
    
    function generateSessionId() {
        // Gera ID único para a sessão (não identificável)
        const stored = sessionStorage.getItem('analytics_session_id');
        if (stored) return stored;
        
        const id = 'sess_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        sessionStorage.setItem('analytics_session_id', id);
        return id;
    }
    
    function getDeviceType() {
        const ua = navigator.userAgent;
        if (/Mobile|Android|iPhone/i.test(ua)) return 'Mobile';
        if (/iPad|Tablet/i.test(ua)) return 'Tablet';
        return 'Desktop';
    }
    
    // ============================================
    // ENVIO SEGURO DE EVENTOS
    // ============================================
    
    async function trackEvent(eventType, eventData = {}) {
        try {
            const event = {
                type: eventType,
                timestamp: new Date().toISOString(),
                page: {
                    url: window.location.href,
                    title: document.title,
                    referrer: document.referrer || ''
                },
                data: eventData
            };
            
            // Envia para API (sem dados sensíveis do cliente)
            const response = await fetch(`${API_URL}/api/analytics/event`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-ID': SESSION_ID
                },
                body: JSON.stringify(event),
                // Não envia cookies ou credenciais
                credentials: 'omit'
            });
            
            if (!response.ok) {
                // Falha silenciosa - não interrompe experiência do usuário
                console.debug('Analytics: evento não enviado');
            }
            
        } catch (error) {
            // Falha silenciosa
            console.debug('Analytics: erro ao enviar evento');
        }
    }
    
    // ============================================
    // RASTREAMENTO AUTOMÁTICO
    // ============================================
    
    // Page view ao carregar
    trackEvent('page_view');
    
    // ============================================
    // RASTREAMENTO DE CLIQUES NO WHATSAPP
    // ============================================
    
    function setupWhatsAppTracking() {
        const whatsappBtns = document.querySelectorAll('[id*="whatsapp"]');
        
        whatsappBtns.forEach(btn => {
            btn.addEventListener('click', function(e) {
                const buttonLocation = this.id.includes('footer') ? 'Footer' : 'Hero';
                trackEvent('whatsapp_click', {
                    buttonLocation: buttonLocation
                });
            }, { passive: true });
        });
    }
    
    // ============================================
    // RASTREAMENTO DE TEMPO E SCROLL
    // ============================================
    
    let startTime = Date.now();
    let maxScrollDepth = 0;
    
    function trackScrollDepth() {
        const scrollHeight = document.documentElement.scrollHeight - window.innerHeight;
        if (scrollHeight > 0) {
            const scrollDepth = Math.round((window.scrollY / scrollHeight) * 100);
            if (scrollDepth > maxScrollDepth) {
                maxScrollDepth = scrollDepth;
            }
        }
    }
    
    // Throttle para scroll
    let scrollTimeout;
    window.addEventListener('scroll', function() {
        if (scrollTimeout) return;
        scrollTimeout = setTimeout(function() {
            trackScrollDepth();
            scrollTimeout = null;
        }, 200);
    }, { passive: true });
    
    // Envia dados ao sair
    window.addEventListener('beforeunload', function() {
        const timeSpent = Math.round((Date.now() - startTime) / 1000);
        
        // Usa sendBeacon para envio assíncrono que não bloqueia
        if (navigator.sendBeacon) {
            const exitData = JSON.stringify({
                type: 'page_exit',
                timestamp: new Date().toISOString(),
                page: {
                    url: window.location.href,
                    title: document.title,
                    referrer: document.referrer || ''
                },
                data: {
                    timeSpent: timeSpent,
                    scrollDepth: maxScrollDepth
                }
            });
            
            navigator.sendBeacon(
                `${API_URL}/api/analytics/event`,
                new Blob([exitData], { type: 'application/json' })
            );
        }
    });
    
    // ============================================
    // INICIALIZAÇÃO
    // ============================================
    
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setupWhatsAppTracking);
    } else {
        setupWhatsAppTracking();
    }
    
    // ============================================
    // API PÚBLICA (para uso manual se necessário)
    // ============================================
    
    window.CompremaisAnalytics = {
        track: function(eventName, data) {
            if (typeof eventName !== 'string') {
                console.warn('Analytics: nome do evento deve ser string');
                return;
            }
            trackEvent(eventName, data);
        },
        
        version: '2.0.0'
    };
    
    console.log('✓ Analytics tracker initialized (v2.0.0)');
    
})();
