window.addEventListener('DOMContentLoaded', () => {
    let counter = document.getElementsByClassName('counter-num');
    if (counter) {
        Array.from(counter).forEach((item) => {
            let start = 0;
            let duration = 3000;
            let end = parseInt(item.getAttribute('data-num'))
            let act_dur = Math.ceil(duration / end)

            let counter_interval = setInterval(() => {
                start++;
                item.innerHTML = `${start}`
                if (start == end) {
                    clearInterval(counter_interval)
                }

            }, act_dur)

        })
    }

    let login_up = document.querySelector('#login')
    let cancel_btn = document.querySelectorAll('.cancel_btn')
    let signUpForm = document.getElementById('signup-form');

    function showDiv(popId) {
        let popDiv = document.querySelector(`#${popId}`);
        let innerDiv = popDiv.querySelector('.alert-pop')
        popDiv.style.display = 'flex';
        setTimeout(() => {
            popDiv.style.opacity = '1';
            innerDiv.style.display = 'inline-block'
            setTimeout(() => {
                innerDiv.style.opacity = '1';
                innerDiv.style.transform = `translateY(0px)`
            }, 50)
        }, 100)
    }

    login_up.addEventListener('click', function () { showDiv('login-popop'); })

    cancel_btn.forEach((remove) => {
        remove.addEventListener('click', function () {
            var pop_p = this.parentElement.parentElement
            var pop_inner_div = this.parentElement
            pop_inner_div.style.opacity = '0';
            pop_inner_div.style.transform = `translateY(500px)`
            setTimeout(() => {
                pop_p.style.opacity = '0';
                pop_inner_div.style.display = 'inline-block'
                setTimeout(() => {
                    pop_p.style.display = 'none';
                }, 700)
            }, 500)
        })
    })

    let otpInp = document.getElementsByClassName('otp-inp');
    
    Array.from(otpInp).forEach((inp) => {
        inp.addEventListener('input', (e) => {
            if (isNaN(e.target.value)) {
                e.target.value = '';
                return;
            }
            else {
                e.target.nextElementSibling.focus()
            }
    
        })
        inp.addEventListener("keyup", function (e) {
            const target = e.target;
            const key = e.key.toLowerCase();
    
            if (key == "backspace" || key == "delete") {
                target.value = "";
                const prev = target.previousElementSibling;
                if (prev) {
                    prev.focus();
                }
                return;
            }
        });
        inp.addEventListener("keydown", function (e) {
            const key = e.key.toLowerCase();
            if (key == "backspace" || key == "delete") {
                e.preventDefault(); // Prevent the default behavior of the "backspace" key
            }
        });
    
    })
    if(signUpForm){
        signUpForm.addEventListener('submit', (e) => {
            e.preventDefault();
            signUpForm.reset()
            showDiv('verification-popop');
        })
    }
})

