// js/particles-config.js
document.addEventListener('DOMContentLoaded', function () {
    tsParticles.load("tsparticles", {
        // 背景设为透明，不遮挡页面本身的背景
        background: {
            color: "transparent"
        },
        particles: {
            number: {
                value: 80,
                density: {
                    enable: true,
                    area: 800
                }
            },
            color: {
                value: ["#4fc3f7", "#81d4fa", "#b3e5fc"]   // 淡蓝色系，可自行修改
            },
            shape: {
                type: "circle"
            },
            opacity: {
                value: 0.6,
                random: true,
                anim: {
                    enable: true,
                    speed: 0.5,
                    opacity_min: 0.2
                }
            },
            size: {
                value: 3,
                random: true,
                anim: {
                    enable: true,
                    speed: 2,
                    size_min: 0.5
                }
            },
            // 连线效果开启，distance 控制连接距离
            links: {
                enable: true,
                distance: 150,
                color: "#4fc3f7",
                opacity: 0.4,
                width: 1
            },
            move: {
                enable: true,
                speed: 1.5,
                direction: "none",
                random: true,
                straight: false,
                outModes: "out"
            }
        },
        // 鼠标交互（可选），如果不需要可以删除整个 interactivity 对象
        interactivity: {
            events: {
                onHover: {
                    enable: true,
                    mode: "repulse"   // 鼠标悬停时粒子推开
                },
                onClick: {
                    enable: true,
                    mode: "push"      // 点击增加粒子
                }
            },
            modes: {
                repulse: {
                    distance: 100,
                    duration: 0.4
                },
                push: {
                    quantity: 4
                }
            }
        },
        detectRetina: true
    });
});
