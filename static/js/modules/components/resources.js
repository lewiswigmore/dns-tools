import { KNOWLEDGE_BASE } from '../data/index.js';

export function ResourcesPage() {
    return {
      conceptModal: false,
      currentConcept: '',
      conceptContent: '',
      loadingConcept: false,
      conceptError: '',
      conceptAnimations: {},
      knowledgeBase: KNOWLEDGE_BASE,
      complexityFilter: 'All',
      categoryFilter: 'All',
      searchQuery: '',
      
      get filteredKnowledgeBase() {
        let items = this.knowledgeBase;

        // Filter by Search Query
        if (this.searchQuery) {
            const query = this.searchQuery.toLowerCase();
            items = items.filter(item => 
                item.title.toLowerCase().includes(query) || 
                item.summary.toLowerCase().includes(query) ||
                item.tags.some(tag => tag.toLowerCase().includes(query))
            );
        }

        // Filter by Category (from URL or selection)
        if (this.categoryFilter !== 'All') {
            if (this.categoryFilter === 'Security') {
                // "Knowledge Base" view - Security focused
                items = items.filter(item => 
                    item.tags.includes('Threat Intel') || 
                    item.tags.includes('Cloud Security') || 
                    item.tags.includes('Malware') ||
                    item.tags.includes('Security')
                );
            } else {
                // Generic tag filter
                items = items.filter(item => item.tags.includes(this.categoryFilter));
            }
        }

        // Filter by Complexity (dropdown)
        if (this.complexityFilter !== 'All') {
            items = items.filter(item => item.complexity === this.complexityFilter);
        }
        
        return items;
      },

      get pageTitle() {
          return this.categoryFilter === 'Security' ? 'Knowledge Base' : 'Content Library';
      },

      init() {
        // Initialize random pulse animations for DNS concepts
        this.initRandomPulseAnimations();

        // Check for params in URL
        const urlParams = new URLSearchParams(window.location.search);
        
        const category = urlParams.get('category');
        if (category) {
            this.categoryFilter = category;
        }

        const concept = urlParams.get('concept');
        if (concept) {
            // Wait a tick for Alpine to initialize
            this.$nextTick(() => {
                this.showConcept(decodeURIComponent(concept));
            });
        }

        // Handle browser back/forward navigation
        window.addEventListener('popstate', () => {
            const params = new URLSearchParams(window.location.search);
            const conceptParam = params.get('concept');
            
            if (conceptParam) {
                this.showConcept(decodeURIComponent(conceptParam));
            } else if (this.conceptModal) {
                this.closeConcept();
            }
        });
      },
      
      initRandomPulseAnimations() {
        const concepts = [
          'A Record', 'AAAA Record', 'CNAME Record', 'MX Record', 
          'TXT Record', 'NS Record', 'PTR Record', 'SRV Record', 'CAA Record',
          'SPF', 'DKIM', 'DMARC'
        ];
        
        // Randomly select 3-4 concepts to pulse
        const numToPulse = Math.floor(Math.random() * 2) + 3; // 3 or 4 concepts
        const shuffled = concepts.sort(() => 0.5 - Math.random());
        const selectedConcepts = shuffled.slice(0, numToPulse);
        
        // Initialize all concepts as not pulsing
        concepts.forEach(concept => {
          this.conceptAnimations[concept] = false;
        });
        
        // Add staggered pulse animations
        selectedConcepts.forEach((concept, index) => {
          setTimeout(() => {
            this.conceptAnimations[concept] = true;
            
            // Stop pulsing after user has been on page for a while (15 seconds)
            setTimeout(() => {
              this.conceptAnimations[concept] = false;
            }, 15000);
          }, index * 800); // Stagger the start times by 800ms
        });
      },
      
      showConcept(conceptName) {
        this.currentConcept = conceptName;
        this.conceptModal = true;
        this.loadConcept(conceptName);
        
        // Update URL with concept query parameter
        const url = new URL(window.location);
        url.searchParams.set('concept', conceptName);
        window.history.pushState({}, '', url);
      },
      
      closeConcept() {
        this.conceptModal = false;
        this.conceptContent = '';
        this.conceptError = '';
        this.currentConcept = '';
        
        // Remove concept query parameter from URL
        const url = new URL(window.location);
        url.searchParams.delete('concept');
        window.history.pushState({}, '', url);
      },
      
      async loadConcept(conceptName) {
        this.loadingConcept = true;
        this.conceptError = '';
        this.conceptContent = '';
        
        try {
          // Check if it's in our Knowledge Base
          const kbItem = this.knowledgeBase.find(item => item.title === conceptName);
          
          if (kbItem) {
             await new Promise(resolve => setTimeout(resolve, 300)); // Small UI delay
             this.conceptContent = kbItem.content;
          } else {
             this.conceptError = 'Concept not found.';
          }
          
        } catch (error) {
          this.conceptError = 'Failed to load detailed explanation. Please try again.';
        } finally {
          this.loadingConcept = false;
        }
      }
    };
  };
