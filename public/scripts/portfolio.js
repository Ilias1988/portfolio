/* ============================================
   PORTFOLIO — script.js
   Author: Ilias Georgopoulos
   ============================================ */

document.addEventListener('DOMContentLoaded', () => {

    // ========================================
    // 1. TYPING EFFECT
    // ========================================
    const typedOutput = document.getElementById('typed-output');
    const phrases = [
        'Cybersecurity Enthusiast',
        'CTF Player',
        'Red Teaming Tool Developer',
        'Web Security Specialist',
        'Automation & AI Builder'
    ];

    let phraseIndex = 0;
    let charIndex = 0;
    let isDeleting = false;
    let typingSpeed = 80;

    function typeEffect() {
        const currentPhrase = phrases[phraseIndex];

        if (isDeleting) {
            typedOutput.textContent = currentPhrase.substring(0, charIndex - 1);
            charIndex--;
            typingSpeed = 40;
        } else {
            typedOutput.textContent = currentPhrase.substring(0, charIndex + 1);
            charIndex++;
            typingSpeed = 80;
        }

        if (!isDeleting && charIndex === currentPhrase.length) {
            isDeleting = true;
            typingSpeed = 2000; // Pause before deleting
        } else if (isDeleting && charIndex === 0) {
            isDeleting = false;
            phraseIndex = (phraseIndex + 1) % phrases.length;
            typingSpeed = 500; // Pause before typing next
        }

        setTimeout(typeEffect, typingSpeed);
    }

    // Start typing after a small delay
    setTimeout(typeEffect, 1000);

    // ========================================
    // 2. NAVBAR — Scroll Effect & Active Link
    // ========================================
    const navbar = document.getElementById('navbar');
    const navLinks = document.querySelectorAll('.nav-link');
    const sections = document.querySelectorAll('.section, .hero');

    function handleNavScroll() {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }

        // Update active nav link
        let current = '';
        sections.forEach(section => {
            const sectionTop = section.offsetTop - 100;
            if (window.scrollY >= sectionTop) {
                current = section.getAttribute('id');
            }
        });

        navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === '#' + current) {
                link.classList.add('active');
            }
        });
    }

    window.addEventListener('scroll', handleNavScroll);
    handleNavScroll(); // Run once on load

    // ========================================
    // 3. MOBILE MENU TOGGLE
    // ========================================
    const navToggle = document.getElementById('navToggle');
    const navMenu = document.getElementById('navMenu');

    navToggle.addEventListener('click', () => {
        navToggle.classList.toggle('active');
        navMenu.classList.toggle('active');
        document.body.style.overflow = navMenu.classList.contains('active') ? 'hidden' : '';
    });

    // Close menu when clicking a link
    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            navToggle.classList.remove('active');
            navMenu.classList.remove('active');
            document.body.style.overflow = '';
        });
    });

    // Close menu on outside click
    document.addEventListener('click', (e) => {
        if (navMenu.classList.contains('active') &&
            !navMenu.contains(e.target) &&
            !navToggle.contains(e.target)) {
            navToggle.classList.remove('active');
            navMenu.classList.remove('active');
            document.body.style.overflow = '';
        }
    });

    // ========================================
    // 4. SCROLL ANIMATIONS (Intersection Observer)
    // ========================================
    const animatedElements = document.querySelectorAll('[data-animate], .timeline-item, .cert-card, .project-card, .tool-card');

    const observerOptions = {
        root: null,
        rootMargin: '0px 0px -80px 0px',
        threshold: 0.1
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry, index) => {
            if (entry.isIntersecting) {
                // Stagger animation for siblings
                const delay = index * 100;
                setTimeout(() => {
                    entry.target.classList.add('visible');
                }, delay);
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    animatedElements.forEach(el => observer.observe(el));

    // ========================================
    // 5. COUNTER ANIMATION (Hero Stats)
    // ========================================
    const statNumbers = document.querySelectorAll('.stat-number');
    let countersStarted = false;

    function animateCounters() {
        statNumbers.forEach(counter => {
            const target = parseInt(counter.getAttribute('data-target'));
            const duration = 2000; // 2 seconds
            const increment = target / (duration / 16);
            let current = 0;

            function updateCounter() {
                current += increment;
                if (current < target) {
                    counter.textContent = Math.floor(current);
                    requestAnimationFrame(updateCounter);
                } else {
                    counter.textContent = target;
                }
            }

            updateCounter();
        });
    }

    // Start counters when hero stats come into view
    const heroStats = document.querySelector('.hero-stats');
    if (heroStats) {
        const statsObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting && !countersStarted) {
                    countersStarted = true;
                    animateCounters();
                    statsObserver.unobserve(entry.target);
                }
            });
        }, { threshold: 0.5 });

        statsObserver.observe(heroStats);
    }

    // ========================================
    // 6. LIGHTBOX (Certificate Zoom)
    // ========================================
    const lightbox = document.getElementById('lightbox');
    const lightboxImage = document.getElementById('lightboxImage');
    const lightboxClose = document.querySelector('.lightbox-close');
    const certImageWrappers = document.querySelectorAll('.cert-image-wrapper');

    certImageWrappers.forEach(wrapper => {
        wrapper.addEventListener('click', () => {
            const img = wrapper.querySelector('.cert-image');
            if (img) {
                lightboxImage.src = img.src;
                lightboxImage.alt = img.alt;
                lightbox.classList.add('active');
                lightbox.setAttribute('aria-hidden', 'false');
                document.body.style.overflow = 'hidden';
            }
        });
    });

    function closeLightbox() {
        lightbox.classList.remove('active');
        lightbox.setAttribute('aria-hidden', 'true');
        document.body.style.overflow = '';
    }

    if (lightboxClose) {
        lightboxClose.addEventListener('click', closeLightbox);
    }

    lightbox.addEventListener('click', (e) => {
        if (e.target === lightbox) {
            closeLightbox();
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && lightbox.classList.contains('active')) {
            closeLightbox();
        }
    });

    // ========================================
    // 7. CERT TABS
    // ========================================
    const certTabs = document.querySelectorAll('.cert-tab');
    const certContents = document.querySelectorAll('.cert-tab-content');

    certTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetTab = tab.getAttribute('data-tab');

            // Update active tab
            certTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            // Show target content
            certContents.forEach(content => {
                content.classList.remove('active');
                if (content.id === 'tab-' + targetTab) {
                    content.classList.add('active');
                    // Re-trigger animations for cards in this tab
                    const cards = content.querySelectorAll('.cert-card');
                    cards.forEach((card, i) => {
                        card.classList.remove('visible');
                        setTimeout(() => card.classList.add('visible'), i * 60);
                    });
                }
            });
        });
    });

    // ========================================
    // 8. KNOWLEDGE BASE CATEGORY CAROUSEL
    // ========================================
    document.querySelectorAll('[data-knowledge-carousel]').forEach(carousel => {
        const tabs = Array.from(carousel.querySelectorAll('[data-knowledge-tab]'));
        const slides = Array.from(carousel.querySelectorAll('[data-knowledge-slide]'));
        const previousButton = carousel.querySelector('[data-knowledge-previous]');
        const nextButton = carousel.querySelector('[data-knowledge-next]');
        const status = carousel.querySelector('[data-knowledge-status]');
        let currentIndex = 0;

        function showSlide(index, focusTab = false) {
            currentIndex = (index + slides.length) % slides.length;

            tabs.forEach((tab, tabIndex) => {
                const isActive = tabIndex === currentIndex;
                tab.classList.toggle('active', isActive);
                tab.setAttribute('aria-selected', String(isActive));
                tab.tabIndex = isActive ? 0 : -1;
            });

            slides.forEach((slide, slideIndex) => {
                slide.hidden = slideIndex !== currentIndex;
            });

            if (status) status.textContent = `${currentIndex + 1} / ${slides.length}`;
            if (focusTab) tabs[currentIndex]?.focus();
        }

        tabs.forEach((tab, index) => {
            tab.addEventListener('click', () => showSlide(index));
            tab.addEventListener('keydown', event => {
                if (event.key === 'ArrowLeft') {
                    event.preventDefault();
                    showSlide(currentIndex - 1, true);
                }
                if (event.key === 'ArrowRight') {
                    event.preventDefault();
                    showSlide(currentIndex + 1, true);
                }
            });
        });

        previousButton?.addEventListener('click', () => showSlide(currentIndex - 1));
        nextButton?.addEventListener('click', () => showSlide(currentIndex + 1));
        showSlide(0);
    });

    // ========================================
    // 9. SMOOTH SCROLL for anchor links
    // ========================================
    function scrollToSection(target, behavior = 'smooth') {
        const navHeight = navbar ? navbar.offsetHeight : 0;
        const breathingRoom = 24;
        const targetTop = target.getBoundingClientRect().top + window.scrollY;

        window.scrollTo({
            top: Math.max(0, targetTop - navHeight - breathingRoom),
            behavior
        });
    }

    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            const targetId = this.getAttribute('href');
            if (!targetId || targetId === '#') return;

            const target = document.querySelector(targetId);
            if (target) {
                e.preventDefault();
                window.history.pushState(null, '', targetId);
                scrollToSection(target);
            }
        });
    });

    // Browser hash navigation can run before fonts and lazy assets settle.
    // Re-align once the page is stable so fixed navigation never covers a title.
    function alignInitialHash() {
        if (!window.location.hash) return;

        const target = document.querySelector(window.location.hash);
        if (!target) return;

        const align = () => requestAnimationFrame(() => scrollToSection(target, 'auto'));
        if (document.fonts?.ready) {
            document.fonts.ready.then(align);
        } else {
            align();
        }
    }

    if (document.readyState === 'complete') {
        alignInitialHash();
    } else {
        window.addEventListener('load', alignInitialHash, { once: true });
    }

    // ========================================
    // 10. CONSOLE EASTER EGG
    // ========================================
    console.log('%c[ilias1988] Access Granted.', 'color: #00ff41; font-size: 16px; font-family: monospace; font-weight: bold;');
    console.log('%cWelcome to my portfolio! Check out my GitHub: https://github.com/Ilias1988', 'color: #8b949e; font-size: 12px; font-family: monospace;');

});
