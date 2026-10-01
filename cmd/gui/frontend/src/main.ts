import './style.css'
import App from './App.svelte'
import {mount} from 'svelte'

// index.html owns the #app element and the asset server serves that file, so
// getElementById cannot miss here -- but its return type says it can, and
// mounting into null would leave a blank window with no error.
const target = document.getElementById('app')
if (!target) {
  throw new Error('index.html is missing its #app mount point')
}

const app = mount(App, {target})

export default app
