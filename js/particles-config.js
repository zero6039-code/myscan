// js/particles-config.js
document.addEventListener('DOMContentLoaded', function () {
    tsParticles.load("tsparticles", {
        background: { color: "transparent" },   // 透明，露出黑色背景
        particles: {
            number: { value: 80, density: { enable: true, area: 800 } },
            color: { value: ["#4fc3f7", "#81d4fa", "#b3e5fc"] },
            shape: { type: "circle" },
            opacity: {
                value: 0.6,
                random: true,
                anim: { enable: true, speed: 0.5, opacity_min: 0.2 }
            },
            size: {
                value: 3,
                random: true,
                anim: { enable: true, speed: 2, size_min: 0.5 }
            },
            links: {
                enable: true,
                distance: 150,
                color: "#4fc3f7",
                opacity: 0.4,
                width: 1
            },
            move: {
                enable: true,
                speed: 4.0,
                direction: "none",
                random: true,
                straight: false,
                outModes: "out"
            }
        },
        interactivity: {
            events: {
                onHover: { enable: true, mode: "repulse" },
                onClick: { enable: true, mode: "push" }
            },
            modes: {
                repulse: { distance: 100, duration: 0.4 },
                push: { quantity: 4 }
            }
        },
        detectRetina: true
    });
});
